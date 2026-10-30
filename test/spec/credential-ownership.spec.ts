import 'jasmine';
import { Database } from '@riao/dbal';
import { Principal } from '@riao/iam';
import {
	AuthenticationResponseJSON, verifyAuthenticationResponse,
	VerifyAuthenticationResponseOpts,
} from '@simplewebauthn/server';
import {
	Fido2Authentication, StoredChallenge,
} from '../../src/authentication-fido2';

describe('FIDO2 credential ownership', () => {
	const principal: Principal = {
		id: '7', login: 'user@example.com', type: 'user', name: 'User',
		create_timestamp: new Date(),
	};
	const response: AuthenticationResponseJSON = {
		id: 'credential', rawId: 'credential', type: 'public-key',
		clientExtensionResults: {},
		response: {
			clientDataJSON: Buffer.from(JSON.stringify({
				challenge: 'challenge',
			})).toString('base64url'),
			authenticatorData: 'auth', signature: 'sig',
		},
	};
	type Verification = Awaited<
		ReturnType<typeof verifyAuthenticationResponse>
	>;
	const verification: Verification = {
		verified: true,
		authenticationInfo: {
			credentialID: response.id, newCounter: 1, userVerified: true,
			credentialDeviceType: 'singleDevice', credentialBackedUp: false,
			origin: 'https://example.com', rpID: 'example.com',
		},
	};
	let auth: Fido2Authentication<Principal>;
	let challenge: StoredChallenge;
	let authenticator: { id: string; principal_id: string | number;
		public_key: string; counter: number };
	let verifier: jasmine.Spy;
	let challenges: jasmine.SpyObj<{
		find: () => Promise<StoredChallenge[]>;
		update: (options: unknown) => Promise<void>;
		findOne: (options: { where: Partial<StoredChallenge> }) =>
			Promise<StoredChallenge | null>;
	}>;
	let credentials: jasmine.SpyObj<{
		findOne: () => Promise<object | null>;
		update: (options: unknown) => Promise<void>;
	}>;

	beforeEach(() => {
		challenge = {
			id: 'challenge', principal_id: principal.id,
			challenge_type: 'authentication', used: false,
			expires: new Date(Date.now() + 60_000),
		};
		authenticator = {
			id: response.id, principal_id: principal.id,
			public_key: 'a2V5', counter: 0,
		};
		verifier = jasmine.createSpy('verifier').and.resolveTo(verification);
		challenges = jasmine.createSpyObj(
			'challenges', ['find', 'update', 'findOne']
		);
		challenges.find.and.callFake(async () => [{ ...challenge }]);
		challenges.update.and.callFake(async (options) => {
			const { set } = options as {
				set: Partial<StoredChallenge>;
			};
			Object.assign(challenge, set);
		});
		challenges.findOne.and.callFake(async ({ where }) =>
			challenge.id === where.id &&
			challenge.consumption_id === where.consumption_id ?
				{ ...challenge } : null
		);
		credentials = jasmine.createSpyObj('credentials', [
			'findOne', 'update',
		]);
		credentials.findOne.and.callFake(async () => authenticator);
		credentials.update.and.resolveTo();
		const principals = jasmine.createSpyObj('principals', ['findOne']);
		principals.findOne.and.resolveTo(principal);
		const db = {
			getQueryRepository: jasmine.createSpy().and.returnValues(
				principals, challenges, credentials
			),
		} as unknown as Database;
		auth = new (class extends Fido2Authentication<Principal> {
			protected override async verifyAuthenticationResponse(
				options: VerifyAuthenticationResponseOpts
			): ReturnType<typeof verifyAuthenticationResponse> {
				return verifier(options);
			}
		})({ db, rpName: 'Test', rpID: 'example.com',
			origin: 'https://example.com' });
	});

	const authenticate = async () => auth.authenticate({
		principalId: principal.id, response,
	});

	it('rejects another principal credential before verification or mutations',
		async () => {
			authenticator.principal_id = 'other-principal';
			expect(await authenticate()).toBeNull();
			expect(verifier).not.toHaveBeenCalled();
			expect(credentials.update).not.toHaveBeenCalled();
			expect(challenges.update).not.toHaveBeenCalled();
		});

	it('accepts the matching owner and preserves the successful baseline flow',
		async () => {
			expect(await authenticate()).toEqual(principal);
			expect(verifier).toHaveBeenCalledTimes(1);
			expect(credentials.update).toHaveBeenCalledWith({
				set: { counter: 1 }, where: { id: response.id },
			});
			const update = challenges.update.calls.mostRecent().args[0] as {
				set: Partial<StoredChallenge>;
				where: Partial<StoredChallenge> & { expires: object };
			};
			expect(update.set).toEqual({
				used: true,
				consumption_id: jasmine.any(String),
			});
			expect(update.where).toEqual(jasmine.objectContaining({
				id: challenge.id,
				principal_id: principal.id,
				challenge_type: 'authentication',
				used: false,
				consumption_id: null,
			}));
		});

	it('matches equivalent string and numeric principal IDs', async () => {
		authenticator.principal_id = 7;
		expect(await authenticate()).toEqual(principal);
	});

	it('preserves null rejection for a missing credential', async () => {
		credentials.findOne.and.resolveTo(null);
		expect(await authenticate()).toBeNull();
		expect(verifier).not.toHaveBeenCalled();
	});

	it('propagates unexpected verifier exceptions without mutations',
		async () => {
			verifier.and.rejectWith(new Error('verification failure'));
			await expectAsync(authenticate())
				.toBeRejectedWithError('verification failure');
			expect(credentials.update).not.toHaveBeenCalled();
		});
});
