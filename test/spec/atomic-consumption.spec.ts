import 'jasmine';
import { Database, UpdateOptions, SelectQuery, gt } from '@riao/dbal';
import { Principal } from '@riao/iam';
import {
	AuthenticationResponseJSON, verifyAuthenticationResponse,
	VerifyAuthenticationResponseOpts,
} from '@simplewebauthn/server';
import {
	Fido2Authentication, StoredChallenge,
} from '../../src/authentication-fido2';
// eslint-disable-next-line max-len
import { AuthenticationFido2Migrations } from '../../src/authentication-fido2-migrations';

describe('Atomic FIDO2 authentication challenge consumption', () => {
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
	let row: StoredChallenge;
	let verifier: jasmine.Spy;
	let challenges: jasmine.SpyObj<{
		find: () => Promise<StoredChallenge[]>;
		update: (options: UpdateOptions<StoredChallenge>) => Promise<void>;
		findOne: (options: SelectQuery<StoredChallenge>) =>
			Promise<StoredChallenge | null>;
	}>;
	let credentials: jasmine.SpyObj<{
		findOne: () => Promise<object | null>;
		update: () => Promise<void>;
	}>;

	beforeEach(() => {
		row = {
			id: 'challenge', principal_id: principal.id,
			challenge_type: 'authentication', used: false,
			expires: new Date(Date.now() + 60_000), consumption_id: null,
		};
		verifier = jasmine.createSpy('verifier').and.resolveTo(verification);
		challenges = jasmine.createSpyObj('challenges', [
			'find', 'update', 'findOne',
		]);
		challenges.find.and.callFake(async () => row.used ? [] : [{ ...row }]);
		challenges.update.and.callFake(async (options) => {
			const where = options.where as Partial<StoredChallenge>;
			const expiry = where.expires as unknown as { value: Date };
			if (
				row.id === where.id &&
				row.principal_id === where.principal_id &&
				row.challenge_type === where.challenge_type &&
				row.used === where.used &&
				row.consumption_id === where.consumption_id &&
				row.expires.getTime() > expiry.value.getTime()
			) {
				Object.assign(row, options.set);
			}
		});
		challenges.findOne.and.callFake(async (options) => {
			const where = options.where as Partial<StoredChallenge>;
			return row.id === where.id &&
				row.consumption_id === where.consumption_id ?
				{ ...row } : null;
		});
		credentials = jasmine.createSpyObj('credentials', [
			'findOne', 'update',
		]);
		credentials.findOne.and.resolveTo({
			id: response.id, principal_id: principal.id,
			public_key: 'a2V5', counter: 0,
		});
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

	it('allows one concurrent success and one counter update', async () => {
		let release!: () => void;
		const barrier = new Promise<void>((resolve) => {
			release = resolve;
		});
		let attempts = 0;
		verifier.and.callFake(async () => {
			if (++attempts === 2) {
				release();
			}
			await barrier;
			return verification;
		});
		const results = await Promise.all([authenticate(), authenticate()]);
		const successes = results.filter((result) => result !== null);
		expect(successes).toEqual([principal]);
		expect(results.filter((result) => result === null).length).toBe(1);
		expect(challenges.update).toHaveBeenCalledTimes(2);
		const receipts = challenges.update.calls.allArgs().map(
			([options]) => String(options.set.consumption_id)
		);
		expect(receipts[0]).not.toEqual(receipts[1]);
		expect(credentials.update).toHaveBeenCalledTimes(1);
		expect(row.used).toBeTrue();
		expect(row.consumption_id).toEqual(jasmine.any(String));
		expect(await authenticate()).toBeNull();
		expect(credentials.update).toHaveBeenCalledTimes(1);
	});

	it('claims only the exact unused, unexpired challenge', async () => {
		jasmine.clock().install();
		try {
			const now = new Date();
			jasmine.clock().mockDate(now);
			expect(await authenticate()).toEqual(principal);
			const where = challenges.update.calls.mostRecent().args[0].where;
			expect(where as object).toEqual({
				id: row.id, principal_id: principal.id,
				challenge_type: 'authentication', used: false,
				consumption_id: null, expires: gt(now),
			});
			const claimed = challenges.findOne.calls.mostRecent().args[0].where;
			expect(claimed as object).toEqual({
				id: row.id, consumption_id: row.consumption_id,
			});
		}
		finally {
			jasmine.clock().uninstall();
		}
	});

	it('rejects a challenge expiring while cryptographic verification runs',
		async () => {
			verifier.and.callFake(async () => {
				row.expires = new Date(0);
				return verification;
			});
			expect(await authenticate()).toBeNull();
			expect(credentials.update).not.toHaveBeenCalled();
			expect(row.used).toBeFalse();
		});

	it('leaves a challenge unused when verification fails', async () => {
		verifier.and.resolveTo({ ...verification, verified: false });
		expect(await authenticate()).toBeNull();
		expect(challenges.update).not.toHaveBeenCalled();
		expect(credentials.update).not.toHaveBeenCalled();
	});

	it('does not update the counter when a different receipt won', async () => {
		row.consumption_id = 'another-attempt';
		expect(await authenticate()).toBeNull();
		expect(credentials.update).not.toHaveBeenCalled();
	});

	it('keeps the challenge consumed if the counter update fails', async () => {
		credentials.update.and.rejectWith(new Error('counter update failed'));
		await expectAsync(authenticate())
			.toBeRejectedWithError('counter update failed');
		expect(row.used).toBeTrue();
		expect(await authenticate()).toBeNull();
	});
});
