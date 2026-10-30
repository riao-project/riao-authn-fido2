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

describe('FIDO2 challenge expiry', () => {
	const principal: Principal = {
		id: '7',
		login: 'user@example.com',
		type: 'user',
		name: 'User',
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

	const registration: RegistrationResponseJSON = {
		id: 'credential', rawId: 'credential', type: 'public-key',
		clientExtensionResults: {},
		response: {
			clientDataJSON: Buffer.from(JSON.stringify({
				challenge: 'challenge',
			})).toString('base64url'),
			attestationObject: 'attestation',
		},
	};

	type ChallengeQuery = {
		where: Pick<
			StoredChallenge,
			'id' | 'principal_id' | 'challenge_type' | 'used'
		>;
	};

	let auth: Fido2Authentication<Principal>;
	let challenge: StoredChallenge;
	let olderChallenge: StoredChallenge;
	let verifier: jasmine.Spy;
	let registrationVerifier: jasmine.Spy;
	let challenges: jasmine.SpyObj<{
		find: (options: ChallengeQuery) => Promise<StoredChallenge[]>;
		update: (options: unknown) => Promise<void>;
		findOne: (options: { where: Partial<StoredChallenge> }) =>
			Promise<StoredChallenge | null>;
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
		olderChallenge = {
			...challenge,
			id: 'older-challenge',
			expires: new Date(Date.now() - 60_000),
		};
		verifier = jasmine.createSpy('verifier')
			.and.resolveTo({
				verified: true,
				authenticationInfo: {
					credentialID: response.id, newCounter: 1,
					userVerified: true, credentialDeviceType: 'singleDevice',
					credentialBackedUp: false, origin: 'https://example.com',
					rpID: 'example.com',
				},
			});
		registrationVerifier = jasmine.createSpy('registrationVerifier')
			.and.resolveTo({ verified: false });
		challenges = jasmine.createSpyObj(
			'challenges', ['find', 'update', 'findOne']
		);
		challenges.find.and.callFake(async (options) =>
			[olderChallenge, challenge].filter((candidate) =>
				candidate.id === options.where.id &&
				candidate.principal_id === options.where.principal_id &&
				candidate.challenge_type === options.where.challenge_type &&
				candidate.used === options.where.used
			)
		);
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
			'findOne', 'update', 'insert',
		]);
		credentials.findOne.and.resolveTo({
			id: response.id, principal_id: principal.id,
			public_key: 'a2V5', counter: 0,
		});
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
					expect(challenges.find).toHaveBeenCalledWith({
						where: {
							id: 'challenge', principal_id: principal.id,
							challenge_type: 'authentication', used: false,
						},
					});
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
					olderChallenge.challenge_type = 'registration';
					challenge.expires = expiry === 'invalid' ?
						new Date('invalid') :
						new Date(
							now.getTime() - (expiry === 'expired' ? 1 : 0)
						);
					const result = await auth.verifyRegistration(
						principal, registration
					);
					expect(result).toEqual({ verified: false });
					expect(challenges.find).toHaveBeenCalledWith({
						where: {
							id: 'challenge', principal_id: principal.id,
							challenge_type: 'registration', used: false,
						},
					});
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
		olderChallenge.challenge_type = 'registration';
		expect(await auth.verifyRegistration(principal, registration))
			.toEqual({ verified: false });
		expect(registrationVerifier).toHaveBeenCalledTimes(1);
		expect(registrationVerifier).toHaveBeenCalledWith(
			jasmine.objectContaining({ expectedChallenge: 'challenge' })
		);
	});

	it('selects the response challenge instead of an older outstanding one',
		async () => {
			expect(await authenticate()).toEqual(principal);
			expect(verifier).toHaveBeenCalledWith(jasmine.objectContaining({
				expectedChallenge: 'challenge',
			}));
		});
});
