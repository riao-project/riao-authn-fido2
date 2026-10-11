import 'jasmine';
import { Database } from '@riao/dbal';
import { Principal } from '@riao/iam';
import {
	AuthenticationResponseJSON, RegistrationResponseJSON,
	verifyAuthenticationResponse, verifyRegistrationResponse,
	VerifyAuthenticationResponseOpts, VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';
import {
	Fido2Authentication, StoredChallenge,
} from '../../src/authentication-fido2';

describe('FIDO2 credential ownership and challenge expiry', () => {
	const principal: Principal = {
		id: '7', login: 'user@example.com', type: 'user', name: 'User',
		create_timestamp: new Date(),
	};
	const response: AuthenticationResponseJSON = {
		id: 'credential', rawId: 'credential', type: 'public-key',
		clientExtensionResults: {},
		response: {
			clientDataJSON: 'data', authenticatorData: 'auth', signature: 'sig',
		},
	};
	const registration: RegistrationResponseJSON = {
		id: 'credential', rawId: 'credential', type: 'public-key',
		clientExtensionResults: {},
		response: {
			clientDataJSON: 'data', attestationObject: 'attestation',
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
	let registrationVerifier: jasmine.Spy;
	let challenges: jasmine.SpyObj<{
		find: () => Promise<StoredChallenge[]>;
		update: (options: unknown) => Promise<void>;
	}>;
	let credentials: jasmine.SpyObj<{
		findOne: () => Promise<object | null>;
		update: (options: unknown) => Promise<void>;
		insert: () => Promise<void>;
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
		registrationVerifier = jasmine.createSpy('registrationVerifier')
			.and.resolveTo({ verified: false });
		challenges = jasmine.createSpyObj('challenges', ['find', 'update']);
		challenges.find.and.callFake(async () => [{ ...challenge }]);
		challenges.update.and.resolveTo();
		credentials = jasmine.createSpyObj('credentials', [
			'findOne', 'update', 'insert',
		]);
		credentials.findOne.and.callFake(async () => authenticator);
		credentials.update.and.resolveTo();
		credentials.insert.and.resolveTo();
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
			protected override async verifyRegistrationResponse(
				options: VerifyRegistrationResponseOpts
			): ReturnType<typeof verifyRegistrationResponse> {
				return registrationVerifier(options);
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
			expect(challenges.update).toHaveBeenCalledWith({
				set: { used: true }, where: { id: challenge.id },
			});
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

	for (const expiry of ['expired', 'at deadline', 'invalid'] as const) {
		it(`rejects ${expiry} authentication expiry before verification`,
			async () => {
				jasmine.clock().install();
				try {
					const now = new Date();
					jasmine.clock().mockDate(now);
					challenge.expires = expiry === 'invalid' ?
						new Date('invalid') :
						new Date(
							now.getTime() - (expiry === 'expired' ? 1 : 0)
						);
					expect(await authenticate()).toBeNull();
					expect(verifier).not.toHaveBeenCalled();
					expect(credentials.findOne).not.toHaveBeenCalled();
					expect(challenges.update).not.toHaveBeenCalled();
				}
				finally {
					jasmine.clock().uninstall();
				}
			});

		it(`rejects ${expiry} registration expiry before verification`,
			async () => {
				jasmine.clock().install();
				try {
					const now = new Date();
					jasmine.clock().mockDate(now);
					challenge.challenge_type = 'registration';
					challenge.expires = expiry === 'invalid' ?
						new Date('invalid') :
						new Date(
							now.getTime() - (expiry === 'expired' ? 1 : 0)
						);
					const result = await auth.verifyRegistration(
						principal, registration
					);
					expect(result).toEqual({ verified: false });
					expect(registrationVerifier).not.toHaveBeenCalled();
					expect(credentials.insert).not.toHaveBeenCalled();
					expect(challenges.update).not.toHaveBeenCalled();
				}
				finally {
					jasmine.clock().uninstall();
				}
			});
	}

	it('continues verifying an unexpired registration', async () => {
		challenge.challenge_type = 'registration';
		expect(await auth.verifyRegistration(principal, registration))
			.toEqual({ verified: false });
		expect(registrationVerifier).toHaveBeenCalledTimes(1);
	});

	it('preserves unexpected verifier exceptions', async () => {
		verifier.and.rejectWith(new Error('verification failure'));
		await expectAsync(authenticate())
			.toBeRejectedWithError('verification failure');
		expect(credentials.update).not.toHaveBeenCalled();
	});
});
