import { createHash, generateKeyPairSync } from 'crypto';
import { Database } from '@riao/dbal';
import { AuthenticationProtection } from '@riao/iam/authentication';
import { Principal } from '@riao/iam';
import {
	AuthenticationResponseJSON,
	verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { Fido2Authentication } from '../../src';
import {
	hasValidClientDataJSON,
	isAuthenticationVerificationError,
} from '../../src/verification-error';

describe('FIDO2 authentication contract', () => {
	let auth: Fido2Authentication<Principal>;
	let principals: jasmine.SpyObj<{ findOne: () => Promise<object | null> }>;
	let challenges: jasmine.SpyObj<{
		find: () => Promise<object[]>;
		update: (options: unknown) => Promise<void>;
		findOne: (options: {
			where: { id: string; consumption_id: string };
		}) => Promise<object | null>;
	}>;
	let credentials: jasmine.SpyObj<{
		findOne: () => Promise<object | null>;
		update: () => Promise<void>;
	}>;
	let protection: jasmine.SpyObj<AuthenticationProtection>;
	let verifier: jasmine.Spy;
	const principal: Principal = {
		id: '7', login: 'user@example.com', type: 'user', name: 'User',
		create_timestamp: new Date(),
	};
	const response: AuthenticationResponseJSON = {
		id: 'Y3JlZGVudGlhbA', rawId: 'Y3JlZGVudGlhbA', type: 'public-key',
		clientExtensionResults: {},
		response: {
			clientDataJSON: Buffer.from(JSON.stringify({
				type: 'webauthn.get', challenge: 'challenge',
				origin: 'https://example.com',
			})).toString('base64url'),
			authenticatorData: 'YXV0aA', signature: 'c2ln',
		},
	};
	const verification: Awaited<
		ReturnType<typeof verifyAuthenticationResponse>
	> = {
		verified: true,
		authenticationInfo: {
			credentialID: response.id, newCounter: 1, userVerified: true,
			credentialDeviceType: 'singleDevice', credentialBackedUp: false,
			origin: 'https://example.com', rpID: 'example.com',
		},
	};
	const challenge = () => ({
		id: 'challenge', principal_id: 7, challenge_type: 'authentication',
		expires: new Date(Date.now() + 60_000), used: false,
	});
	const authenticate = async () =>
		auth.authenticate({ principalId: 7, response });

	beforeEach(() => {
		principals = jasmine.createSpyObj('principals', ['findOne']);
		principals.findOne.and.resolveTo(principal);
		challenges = jasmine.createSpyObj('challenges', [
			'find', 'update', 'findOne',
		]);
		challenges.find.and.resolveTo([challenge()]);
		let consumptionId: string | null = null;
		challenges.update.and.callFake(async (options) => {
			const { set } = options as {
				set: { consumption_id?: string };
			};
			consumptionId = set.consumption_id ?? null;
		});
		challenges.findOne.and.callFake(async ({ where }) =>
			where.id === 'challenge' &&
			where.consumption_id === consumptionId ?
				{ id: 'challenge', consumption_id: consumptionId } : null
		);
		credentials = jasmine.createSpyObj(
			'credentials',
			['findOne', 'update']
		);
		credentials.findOne.and.resolveTo({
			id: response.id, principal_id: 7, public_key: 'a2V5', counter: 0,
		});
		credentials.update.and.resolveTo();
		protection = jasmine.createSpyObj('protection', [
			'beforeAttempt', 'onFailure', 'onSuccess',
		]);
		protection.beforeAttempt.and.resolveTo({ allowed: true });
		protection.onFailure.and.resolveTo();
		protection.onSuccess.and.resolveTo();
		const db = {
			getQueryRepository: jasmine.createSpy().and.returnValues(
				principals, challenges, credentials
			),
		} as unknown as Database;
		auth = new Fido2Authentication({
			db, rpName: 'Test', rpID: 'example.com',
			origin: 'https://example.com', authenticationProtection: protection,
		});
		verifier = spyOn(
			auth as unknown as {
				verifyAuthenticationResponse:
					typeof verifyAuthenticationResponse;
			},
			'verifyAuthenticationResponse'
		).and.resolveTo(verification);
	});

	it('runs before and success hooks after a verified active principal',
		async () => {
			protection.onSuccess.and.callFake(async () => {
				expect(credentials.update).toHaveBeenCalledTimes(1);
				expect(challenges.update).toHaveBeenCalledTimes(1);
			});
			expect(await authenticate()).toEqual(principal);
			expect(protection.beforeAttempt).toHaveBeenCalledWith({
				scheme: 'fido2', subject: '7',
			});
			expect(protection.onSuccess).toHaveBeenCalledTimes(1);
			expect(protection.onFailure).not.toHaveBeenCalled();
			expect(credentials.update).toHaveBeenCalledTimes(1);
		});

	it(
		'returns null for blocked attempts without counting failure',
		async () => {
			protection.beforeAttempt.and.resolveTo({
				allowed: false, retryAfterSeconds: 30,
			});
			expect(await authenticate()).toBeNull();
			expect(principals.findOne).not.toHaveBeenCalled();
			expect(protection.onFailure).not.toHaveBeenCalled();
			expect(protection.onSuccess).not.toHaveBeenCalled();
		}
	);

	it('rejects inactive principals before verification', async () => {
		principals.findOne.and.resolveTo(null);
		expect(await authenticate()).toBeNull();
		expect(verifier).not.toHaveBeenCalled();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
	});

	it('counts missing challenges as authentication failures', async () => {
		challenges.find.and.resolveTo([]);
		expect(await authenticate()).toBeNull();
		expect(verifier).not.toHaveBeenCalled();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
	});

	it('rejects missing credentials', async () => {
		credentials.findOne.and.resolveTo(null);
		expect(await authenticate()).toBeNull();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
		expect(verifier).not.toHaveBeenCalled();
	});

	it(
		'counts verifier false and known assertion errors as failures',
		async () => {
			verifier.and.resolveTo({ ...verification, verified: false });
			expect(await authenticate()).toBeNull();
			verifier.and.rejectWith(
				new Error('User not present during authentication')
			);
			expect(await authenticate()).toBeNull();
			expect(protection.onFailure).toHaveBeenCalledTimes(2);
			expect(challenges.update).not.toHaveBeenCalled();
			expect(credentials.update).not.toHaveBeenCalled();
		}
	);

	it('recognizes real verifier challenge and origin mismatches', async () => {
		verifier.and.callThrough();
		for (const field of ['challenge', 'origin']) {
			const clientDataJSON = Buffer.from(JSON.stringify({
				type: 'webauthn.get', challenge: 'challenge',
				origin: 'https://example.com', [field]: 'wrong',
			})).toString('base64url');
			expect(await auth.authenticate({
				principalId: 7,
				response: {
					...response,
					response: { ...response.response, clientDataJSON },
				},
			})).toBeNull();
		}
		expect(protection.onFailure).toHaveBeenCalledTimes(2);
		expect(credentials.update).not.toHaveBeenCalled();
	});

	it('recognizes real verifier malformed authenticator data', async () => {
		verifier.and.callThrough();
		expect(await authenticate()).toBeNull();
		expect(protection.onFailure).toHaveBeenCalledTimes(1);
		expect(credentials.update).not.toHaveBeenCalled();
	});

	it('maps real verifier errors to authentication failures',
		async () => {
			verifier.and.callThrough();
			const clientData = (overrides: object = {}) => Buffer.from(
				JSON.stringify({
					type: 'webauthn.get',
					challenge: 'challenge',
					origin: 'https://example.com',
					...overrides,
				})
			).toString('base64url');
			const authenticatorData = (
				flags: number,
				rpID = 'example.com',
				counter = 1
			) => {
				const data = Buffer.alloc(37);
				if (rpID) {
					createHash('sha256').update(rpID).digest().copy(data);
				}
				data[32] = flags;
				data.writeUInt32BE(counter, 33);
				return data.toString('base64url');
			};
			const { publicKey: ecPublicKey } = generateKeyPairSync('ec', {
				namedCurve: 'prime256v1',
			});
			const jwk = ecPublicKey.export({ format: 'jwk' });
			if (!jwk.x || !jwk.y) {
				throw new Error('Generated EC key has no coordinates');
			}
			const cosePublicKey = Buffer.concat([
				Buffer.from([
					0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20,
				]),
				Buffer.from(jwk.x, 'base64url'),
				Buffer.from([0x22, 0x58, 0x20]),
				Buffer.from(jwk.y, 'base64url'),
			]).toString('base64');
			const makeResponse = (
				overrides: {
					id?: string;
					rawId?: string;
					type?: string;
					clientDataJSON?: string;
					authenticatorData?: string;
					signature?: string;
					userHandle?: unknown;
				} = {},
				clientDataOverrides: object = {}
			): AuthenticationResponseJSON => ({
				...response,
				...overrides,
				response: {
					...response.response,
					...overrides,
					clientDataJSON:
						overrides.clientDataJSON ??
						clientData(clientDataOverrides),
				},
			} as AuthenticationResponseJSON);

			const cases: Array<{
				name: string;
				response: AuthenticationResponseJSON;
				counter?: number;
				publicKey?: string;
			}> = [
				{
					name: 'credential ID encoding mismatch',
					response: makeResponse({ rawId: 'different' }),
				},
				{
					name: 'unexpected credential type',
					response: makeResponse({ type: 'unexpected' }),
				},
				{
					name: 'unexpected authentication response type',
					response: makeResponse({}, { type: 'webauthn.create' }),
				},
				{
					name: 'unexpected challenge',
					response: makeResponse({}, { challenge: 'wrong' }),
				},
				{
					name: 'unexpected origin',
					response: makeResponse(
						{},
						{ origin: 'https://wrong.example' }
					),
				},
				{
					name: 'invalid authenticator data encoding',
					response: makeResponse({ authenticatorData: '!' }),
				},
				{
					name: 'invalid signature encoding',
					response: makeResponse({ signature: '!' }),
				},
				{
					name: 'invalid user handle type',
					response: makeResponse({ userHandle: 7 }),
				},
				{
					name: 'invalid token binding type',
					response: makeResponse({}, { tokenBinding: 'invalid' }),
				},
				{
					name: 'invalid token binding status',
					response: makeResponse({}, {
						tokenBinding: { status: 'invalid' },
					}),
				},
				{
					name: 'short authenticator data',
					response: makeResponse({
						authenticatorData: Buffer.alloc(1)
							.toString('base64url'),
					}),
				},
				{
					name: 'leftover authenticator data',
					response: makeResponse({
						authenticatorData: Buffer.alloc(38)
							.toString('base64url'),
					}),
				},
				{
					name: 'unexpected RP ID hash',
					response: makeResponse({
						authenticatorData: authenticatorData(0x05, ''),
					}),
				},
				{
					name: 'user presence flag missing',
					response: makeResponse({
						authenticatorData: authenticatorData(0x04),
					}),
				},
				{
					name: 'user verification flag missing',
					response: makeResponse({
						authenticatorData: authenticatorData(0x01),
					}),
				},
				{
					name: 'counter below stored value',
					response: makeResponse({
						authenticatorData: authenticatorData(
							0x05,
							'example.com',
							1
						),
					}),
					counter: 1,
				},
				{
					name: 'impossible backup flags',
					response: makeResponse({
						authenticatorData: authenticatorData(0x15),
					}),
				},
				{
					name: 'malformed ECDSA signature structure',
					response: makeResponse({
						signature: Buffer.from([0x30, 0]).toString('base64url'),
					}),
					publicKey: cosePublicKey,
				},
				{
					name: 'invalid ECDSA signature component length',
					response: makeResponse({
						signature: Buffer.concat([
							Buffer.from([0x30, 0x45, 0x02, 0x21]),
							Buffer.alloc(33, 1),
							Buffer.from([0x02, 0x20]),
							Buffer.alloc(32, 1),
						]).toString('base64url'),
					}),
					publicKey: cosePublicKey,
				},
			];

			for (const testCase of cases) {
				credentials.findOne.and.resolveTo({
					id: response.id,
					principal_id: 7,
					public_key: testCase.publicKey ?? 'a2V5',
					counter: testCase.counter ?? 0,
				});
				expect(await auth.authenticate({
					principalId: 7,
					response: testCase.response,
				})).withContext(testCase.name).toBeNull();
			}
			expect(protection.onFailure).toHaveBeenCalledTimes(cases.length);
			expect(credentials.update).not.toHaveBeenCalled();
		});

	it(
		'rejects malformed client JSON without swallowing ' +
			'unrelated SyntaxErrors',
		async () => {
			expect(await auth.authenticate({
				principalId: 7,
				response: {
					...response,
					response: { ...response.response, clientDataJSON: 'eA' },
				},
			})).toBeNull();
			const failure = new SyntaxError('corrupted stored key');
			verifier.and.rejectWith(failure);
			await expectAsync(authenticate()).toBeRejectedWith(failure);
			expect(protection.onFailure).toHaveBeenCalledTimes(1);
		}
	);

	it('propagates counter persistence errors without counting failure',
		async () => {
			const outage = new Error('counter storage unavailable');
			credentials.update.and.rejectWith(outage);
			await expectAsync(authenticate()).toBeRejectedWith(outage);
			expect(challenges.findOne).toHaveBeenCalledTimes(1);
			expect(protection.onFailure).not.toHaveBeenCalled();
			expect(protection.onSuccess).not.toHaveBeenCalled();
		});

	it('propagates crypto and database outages without counting failures',
		async () => {
			const outage = new Error('service unavailable');
			verifier.and.rejectWith(outage);
			await expectAsync(authenticate()).toBeRejectedWith(outage);
			verifier.and.resolveTo(verification);
			challenges.update.and.rejectWith(outage);
			await expectAsync(authenticate()).toBeRejectedWith(outage);
			expect(protection.onFailure).not.toHaveBeenCalled();
			expect(protection.onSuccess).not.toHaveBeenCalled();
		});

	it('propagates protection outages', async () => {
		const outage = new Error('protection unavailable');
		protection.beforeAttempt.and.rejectWith(outage);
		await expectAsync(authenticate()).toBeRejectedWith(outage);
		expect(verifier).not.toHaveBeenCalled();
		expect(protection.onFailure).not.toHaveBeenCalled();
	});

	it('never treats success-hook or counter outages as failed credentials',
		async () => {
			const outage = new Error('storage unavailable');
			credentials.update.and.rejectWith(outage);
			await expectAsync(authenticate()).toBeRejectedWith(outage);
			expect(protection.onFailure).not.toHaveBeenCalled();
			credentials.update.and.resolveTo();
			protection.onSuccess.and.rejectWith(outage);
			await expectAsync(authenticate()).toBeRejectedWith(outage);
			expect(protection.onFailure).not.toHaveBeenCalled();
		});

	it('recognizes only known SimpleWebAuthn validation errors', () => {
		for (const message of [
			'Missing credential ID',
			'Unexpected authentication response challenge "bad", ' +
				'expected "good"',
			'Unexpected authentication response origin "bad", ' +
				'expected "good"',
			'Authenticator data was 1 bytes, expected at least 37 bytes',
			'Response counter value 1 was lower than expected 2',
		]) {
			expect(isAuthenticationVerificationError(new Error(message)))
				.toBeTrue();
		}
		expect(isAuthenticationVerificationError(new Error('crypto outage')))
			.toBeFalse();
		expect(isAuthenticationVerificationError({
			name: 'UnexpectedRPIDHash',
		}))
			.toBeFalse();
		expect(hasValidClientDataJSON(null)).toBeFalse();
	});
});
