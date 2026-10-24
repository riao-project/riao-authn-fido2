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
	const verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>> = {
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
	const authenticate = () => auth.authenticate({ principalId: 7, response });

	beforeEach(() => {
		principals = jasmine.createSpyObj('principals', ['findOne']);
		principals.findOne.and.resolveTo(principal);
		challenges = jasmine.createSpyObj('challenges', [
			'find', 'update',
		]);
		challenges.find.and.resolveTo([challenge()]);
		challenges.update.and.resolveTo();
		credentials = jasmine.createSpyObj('credentials', ['findOne', 'update']);
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
				verifyAuthenticationResponse: typeof verifyAuthenticationResponse;
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

	it('returns null for blocked attempts without counting failure', async () => {
		protection.beforeAttempt.and.resolveTo({
			allowed: false, retryAfterSeconds: 30,
		});
		expect(await authenticate()).toBeNull();
		expect(principals.findOne).not.toHaveBeenCalled();
		expect(protection.onFailure).not.toHaveBeenCalled();
		expect(protection.onSuccess).not.toHaveBeenCalled();
	});

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

	it('counts verifier false and known assertion errors as failures', async () => {
		verifier.and.resolveTo({ ...verification, verified: false });
		expect(await authenticate()).toBeNull();
		verifier.and.rejectWith(new Error('User not present during authentication'));
		expect(await authenticate()).toBeNull();
		expect(protection.onFailure).toHaveBeenCalledTimes(2);
		expect(challenges.update).not.toHaveBeenCalled();
		expect(credentials.update).not.toHaveBeenCalled();
	});

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

	it('rejects malformed client JSON without swallowing unrelated SyntaxErrors',
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
		});

	it('propagates counter persistence errors without counting failure',
		async () => {
			const outage = new Error('counter storage unavailable');
			credentials.update.and.rejectWith(outage);
			await expectAsync(authenticate()).toBeRejectedWith(outage);
			expect(challenges.update).not.toHaveBeenCalled();
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
			'Unexpected authentication response challenge "bad", expected "good"',
			'Unexpected authentication response origin "bad", expected "good"',
			'Authenticator data was 1 bytes, expected at least 37 bytes',
			'Response counter value 1 was lower than expected 2',
		]) {
			expect(isAuthenticationVerificationError(new Error(message)))
				.toBeTrue();
		}
		expect(isAuthenticationVerificationError(new Error('crypto outage')))
			.toBeFalse();
		expect(isAuthenticationVerificationError({ name: 'UnexpectedRPIDHash' }))
			.toBeFalse();
		expect(hasValidClientDataJSON(null)).toBeFalse();
	});
});
