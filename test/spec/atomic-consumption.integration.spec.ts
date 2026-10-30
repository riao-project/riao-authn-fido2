import 'jasmine';
import { DatabaseRecordId } from '@riao/dbal';
import { Principal } from '@riao/iam';
import {
	AuthMigrations,
} from '@riao/iam/auth/auth-migrations';
import {
	AuthenticationResponseJSON, VerifyAuthenticationResponseOpts,
	verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import {
	AuthenticationFido2Migrations,
} from '../../src/authentication-fido2-migrations';
import { Fido2Authentication } from '../../src/authentication-fido2';
import { createDatabase, runMigrations } from '../database';

describe('Atomic FIDO2 authentication challenge consumption (database)', () => {
	const db = createDatabase('authentication-fido2-atomic-test');
	const verification: Awaited<
		ReturnType<typeof verifyAuthenticationResponse>
	> = {
		verified: true,
		authenticationInfo: {
			credentialID: 'atomic-consumption-credential',
			newCounter: 1,
			userVerified: true,
			credentialDeviceType: 'singleDevice',
			credentialBackedUp: false,
			origin: 'https://example.com',
			rpID: 'example.com',
		},
	};
	const response: AuthenticationResponseJSON = {
		id: 'atomic-consumption-credential',
		rawId: 'atomic-consumption-credential',
		type: 'public-key',
		clientExtensionResults: {},
		response: {
			clientDataJSON: Buffer.from(JSON.stringify({
				challenge: 'atomic-consumption-challenge',
			})).toString('base64url'),
			authenticatorData: 'auth',
			signature: 'sig',
		},
	};
	let principalId: DatabaseRecordId;
	let principal: Principal;
	let auth: Fido2Authentication<Principal>;
	let verify:
		(options: VerifyAuthenticationResponseOpts) =>
			ReturnType<typeof verifyAuthenticationResponse> =
				async () => verification;

	beforeAll(async () => {
		await db.init();
		await runMigrations(db, new AuthMigrations());
		await runMigrations(db, new AuthenticationFido2Migrations());

		auth = new (class extends Fido2Authentication<Principal> {
			protected override async verifyAuthenticationResponse(
				options: VerifyAuthenticationResponseOpts
			): ReturnType<typeof verifyAuthenticationResponse> {
				return verify(options);
			}
		})({
			db,
			rpName: 'Test RP',
			rpID: 'example.com',
			origin: 'https://example.com',
		});

		const inserted = await auth.principalRepo.insertOne({
			record: {
				login: 'atomic-consumption@example.com',
				type: 'user',
				name: 'Atomic consumption test',
			},
		});
		principalId = inserted.id!;
		principal = (await auth.principalRepo.findById(principalId))!;

		await auth.credentialRepo.insert({
			records: [{
				id: response.id,
				principal_id: principalId,
				public_key: Buffer.from('test-key').toString('base64'),
				counter: 0,
			}],
		});
		await auth.challengeRepo.insert({
			records: [{
				id: 'atomic-consumption-challenge',
				principal_id: principalId,
				challenge_type: 'authentication',
				expires: new Date(Date.now() + 60_000),
				used: false,
			}],
		});
	});

	afterAll(async () => {
		await db.disconnect();
	});

	it('allows exactly one concurrent claim and rejects subsequent replay',
		async () => {
			let release!: () => void;
			const verificationBarrier = new Promise<void>((resolve) => {
				release = resolve;
			});
			let verificationAttempts = 0;
			verify = async () => {
				if (++verificationAttempts === 2) {
					release();
				}
				await verificationBarrier;
				return verification;
			};

			const credentials = { principalId, response };
			const results = await Promise.all([
				auth.authenticate(credentials),
				auth.authenticate(credentials),
			]);

			expect(results.filter((result) => result !== null)).toEqual([
				principal,
			]);
			expect(results.filter((result) => result === null).length).toBe(1);

			const challenge = await auth.challengeRepo.findOne({
				where: { id: 'atomic-consumption-challenge' },
			});
			expect(challenge?.used).toBeTrue();
			expect(challenge?.consumption_id).toEqual(jasmine.any(String));

			const credential = await auth.credentialRepo.findOne({
				where: { id: response.id },
			});
			expect(Number(credential?.counter)).toBe(1);
			expect(await auth.authenticate(credentials)).toBeNull();
		});
});
