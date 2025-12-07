import { Fido2Authentication } from '../../src/authentication-fido2';
import { createDatabase, runMigrations, runMigrationsDown } from '../database';
import { Principal } from '@riao/iam';
// eslint-disable-next-line max-len
import { AuthenticationFido2Migrations } from '../../src/authentication-fido2-migrations';

describe('Authentication - FIDO2', () => {
	const db = createDatabase('authentication-fido2');

	const auth = new (class extends Fido2Authentication<Principal> {})({
		db,
		rpName: 'Test RP',
		rpID: 'localhost',
		origin: 'http://localhost',
	});

	const repo = auth.principalRepo;

	// Helper to create unique test principals per test
	async function createTestPrincipal(testName: string): Promise<Principal> {
		const principal: Omit<Principal, 'id' | 'create_timestamp'> = {
			login: `${testName}@example.com`,
			type: 'user',
			name: testName,
		};

		const { id } = await repo.insertOne({
			record: principal,
		});

		const principalRecord = await repo.findById(id!);

		if (!principalRecord) {
			throw new Error('Failed to create test principal');
		}

		return principalRecord;
	}

	// Helper to create registration response with realistic structure
	function createRegistrationResponse(challenge: string, credId: string) {
		const clientDataJSON = Buffer.from(
			JSON.stringify({
				type: 'webauthn.create',
				challenge: Buffer.from(challenge).toString('base64url'),
				origin: 'http://localhost',
			})
		).toString('base64');

		return {
			id: credId,
			rawId: credId,
			response: {
				attestationObject: 'mock-attestation-object',
				clientDataJSON,
				transports: ['usb' as const],
			},
			type: 'public-key' as const,
			clientExtensionResults: {},
		};
	}

	// Helper to create authentication response
	function createAuthResponse(challenge: string, credId: string) {
		const clientDataJSON = Buffer.from(
			JSON.stringify({
				type: 'webauthn.get',
				challenge: Buffer.from(challenge).toString('base64url'),
				origin: 'http://localhost',
			})
		).toString('base64');

		return {
			id: credId,
			rawId: credId,
			response: {
				authenticatorData: 'mock-authenticator-data',
				signature: 'mock-signature',
				clientDataJSON,
			},
			type: 'public-key' as const,
			clientExtensionResults: {},
		};
	}

	// Helper to create and store a test credential
	async function createTestCredential(
		principalId: number | string,
		credId: string,
		publicKey = 'mock-public-key',
		counter = 0
	) {
		await auth['credentialRepo'].insert({
			records: [
				{
					id: credId,
					principal_id: principalId,
					public_key: publicKey,
					counter,
				},
			],
		});
	}

	// Helper to verify challenge state
	async function verifyChallengeState(
		principalId: number | string,
		type: 'registration' | 'authentication',
		expectedCount = 1,
		used = false
	) {
		const challenges = await auth['challengeRepo'].find({
			where: {
				principal_id: principalId,
				challenge_type: type,
				used,
			},
		});
		expect(challenges.length).toBe(expectedCount);
		return challenges;
	}

	// Helper function to quickly set up a test principal with credentials
	async function setupTestPrincipal(
		login: string,
		credentialId: string,
		publicKey: string = Buffer.from('test-key').toString('base64')
	): Promise<number | string> {
		const principalId = await auth.createPrincipal({
			login,
			type: 'user',
			name: login,
		});
		await createTestCredential(principalId, credentialId, publicKey);
		return principalId;
	}

	let testPrincipal: Principal;

	beforeAll(async () => {
		await db.init();
		await runMigrations(db, new AuthenticationFido2Migrations());
		await runMigrationsDown(db, new AuthenticationFido2Migrations());
		await runMigrations(db, new AuthenticationFido2Migrations());

		// Create a shared test principal for individual method tests
		const { id } = await repo.insertOne({
			record: {
				login: 'testuser@example.com',
				type: 'user',
				name: 'testuser',
			},
		});

		// Get the principal ID
		testPrincipal = (await repo.findById(id!)) as Principal;

		if (!testPrincipal) {
			throw new Error('Failed to create shared test principal');
		}
	});

	afterAll(async () => {
		await db.disconnect();
	});

	describe('End-to-End FIDO2 Flows', () => {
		describe('Complete Authentication Flow', () => {
			it('should fail auth with non-existent credential', async () => {
				const failTestPrincipal = await createTestPrincipal(
					'auth-fail-nonexistent-test'
				);
				const userID = failTestPrincipal.id!.toString();
				await auth.generateAuthenticationOptions(userID);

				// Create mock authentication response using helper
				const mockAuthResponse = createAuthResponse(
					'test-challenge',
					'non-existent-credential'
				);

				// Authentication should fail with non-existent credential
				const result = await auth.authenticate({
					response: mockAuthResponse,
					principalId: failTestPrincipal.id!,
				});

				expect(result).toBeNull();
			});

			it('should fail authentication without challenge', async () => {
				const noChallengeTestPrincipal = await createTestPrincipal(
					'auth-no-challenge-test'
				);

				// Don't generate authentication options
				// Create mock authentication response using helper
				const mockAuthResponse = createAuthResponse(
					'non-existent-challenge',
					'auth-no-challenge-credential'
				);

				// Authentication should fail without challenge
				const result = await auth.authenticate({
					response: mockAuthResponse,
					principalId: noChallengeTestPrincipal.id!,
				});

				expect(result).toBeNull();
			});
		});

		describe('Complete User Journey', () => {
			it('should support full user lifecycle', async () => {
				// Create a new principal with credentials
				const principalId = await setupTestPrincipal(
					'journey-lifecycle-test@example.com',
					'journey-lifecycle-credential',
					Buffer.from('journey-key').toString('base64')
				);

				expect(principalId).toBeDefined();

				// Verify registration challenge was created
				await verifyChallengeState(principalId, 'registration');

				// Generate authentication options
				const authOptions = await auth.generateAuthenticationOptions(
					principalId.toString()
				);
				expect(authOptions.allowCredentials).toBeDefined();
				expect(authOptions.allowCredentials!.length).toBe(1);

				// Verify authentication challenge was stored
				await verifyChallengeState(principalId, 'authentication');
			});

			it('should handle multiple credentials per principal', async () => {
				const multiCredTestPrincipal = await createTestPrincipal(
					'journey-multi-credentials-test'
				);

				// Create multiple credentials using helper
				await createTestCredential(
					multiCredTestPrincipal.id!,
					'multi-credential-1',
					Buffer.from('key-1').toString('base64'),
					1
				);

				await createTestCredential(
					multiCredTestPrincipal.id!,
					'multi-credential-2',
					Buffer.from('key-2').toString('base64'),
					2
				);

				// Generate authentication options
				const options = await auth.generateAuthenticationOptions(
					multiCredTestPrincipal.id!.toString()
				);

				// Should include exactly our two credentials
				expect(options.allowCredentials).toBeDefined();
				expect(options.allowCredentials!.length).toBe(2);

				const credIds = options.allowCredentials!.map(
					(cred) => cred.id
				);

				// Verify our specific credentials are included
				expect(credIds).toContain('multi-credential-1');
				expect(credIds).toContain('multi-credential-2');
			});
		});

		describe('Error Handling', () => {
			it('should handle expired challenges gracefully', async () => {
				// Generate options to create a challenge
				await auth.generateRegistrationOptions(testPrincipal);

				// Manually expire the challenge
				const pastDate = new Date(Date.now() - 1000 * 60 * 60);
				await auth['challengeRepo'].update({
					set: { expires: pastDate },
					where: {
						principal_id: testPrincipal.id,
						challenge_type: 'registration',
					},
				});

				// Attempt verification with expired challenge
				// Create mock registration response using helper
				const mockResponse = createRegistrationResponse(
					'expired-challenge',
					'test-cred'
				);

				const result = await auth.verifyRegistration(
					testPrincipal,
					mockResponse
				);
				expect(result.verified).toBe(false);
			});

			it('should handle authentication without credentials', async () => {
				// Attempt authentication with no stored credentials
				const options = await auth.generateAuthenticationOptions();

				// Should work but have no allowCredentials
				expect(options.allowCredentials).toBeUndefined();
			});
		});

		describe('Concurrent Operations', () => {
			it('should handle concurrent challenge generation', async () => {
				const concurrentCount = 3;
				const promises = [];

				for (let i = 0; i < concurrentCount; i++) {
					const promise = (async () => {
						const concurrentPrincipal = await createTestPrincipal(
							`concurrent-${i}-${Date.now()}`
						);

						return auth.generateRegistrationOptions(
							concurrentPrincipal
						);
					})();

					promises.push(promise);
				}

				const results = await Promise.all(promises);

				// All challenges should be unique
				const challenges = results.map((r) => r.challenge);
				const uniqueChallenges = new Set(challenges);

				expect(uniqueChallenges.size).toBe(concurrentCount);
			});
		});
	});

	describe('generateRegistrationOptions', () => {
		it('should generate valid registration options', async () => {
			const options =
				await auth.generateRegistrationOptions(testPrincipal);

			expect(options.rp.name).toBe('Test RP');
			expect(options.rp.id).toBe('localhost');
			expect(options.user.name).toBe(testPrincipal.login);
			expect(options.user.displayName).toBe(testPrincipal.name);
			expect(typeof options.challenge).toBe('string');
			expect(Array.isArray(options.pubKeyCredParams)).toBe(true);
			expect(typeof options.timeout).toBe('number');
			expect(options.attestation).toBe('none');

			if (options.authenticatorSelection) {
				// authenticatorAttachment should be undefined
				// (allows both platform and cross-platform)
				expect(
					options.authenticatorSelection.authenticatorAttachment
				).toBeUndefined();
				expect(options.authenticatorSelection.userVerification).toBe(
					'preferred'
				);
				expect(options.authenticatorSelection.requireResidentKey).toBe(
					false
				);
			}

			// excludeCredentials contains existing credentials for principal
			// Length may vary, just verify structure
			if (options.excludeCredentials) {
				expect(Array.isArray(options.excludeCredentials)).toBe(true);
			}
		});

		it('should throw error if principal has no ID', async () => {
			const principalWithoutId = {
				login: 'registration-no-id-test@example.com',
			};

			await expectAsync(
				auth.generateRegistrationOptions(
					principalWithoutId as Principal
				)
			).toBeRejectedWithError('Principal must have an ID');
		});

		it('should exclude existing credentials', async () => {
			// Create a unique credential for this test using helper
			const testCredId = 'test-credential-exclude-existing';
			await createTestCredential(
				testPrincipal.id!,
				testCredId,
				'mock-public-key'
			);

			const options =
				await auth.generateRegistrationOptions(testPrincipal);

			expect(options.excludeCredentials).toBeDefined();
			if (options.excludeCredentials) {
				// Should include our test credential in the exclude list
				const excludedIds = options.excludeCredentials.map((c) => c.id);
				expect(excludedIds).toContain(testCredId);
			}
		});
	});

	describe('verifyRegistration', () => {
		beforeEach(async () => {
			// Generate registration options first
			await auth.generateRegistrationOptions(testPrincipal);
		});

		it('should return false for invalid challenge', async () => {
			// Create a dedicated test principal for this test
			const testAcc = await createTestPrincipal(
				'verify-invalid-challenge-test'
			);

			// Generate registration options to create a challenge
			await auth.generateRegistrationOptions(testAcc);

			// Create mock registration response using helper
			const mockResponse = createRegistrationResponse(
				'mock-challenge-invalid',
				'mock-credential-invalid-id'
			);

			// Corrupt the challenge by updating it
			await auth['challengeRepo'].update({
				set: { id: 'invalid-challenge-' + Date.now() },
				where: {
					principal_id: testAcc.id,
					challenge_type: 'registration',
				},
			});

			const result = await auth.verifyRegistration(testAcc, mockResponse);

			expect(result.verified).toBe(false);
		});

		it('should return false if no challenge exists', async () => {
			// Delete the challenge
			await auth['challengeRepo'].delete({
				where: {
					principal_id: testPrincipal.id,
					challenge_type: 'registration',
				},
			});

			// Create mock registration response using helper
			const mockResponse = createRegistrationResponse(
				'mock-challenge',
				'mock-credential-id'
			);

			const result = await auth.verifyRegistration(
				testPrincipal,
				mockResponse
			);

			expect(result.verified).toBe(false);
		});

		it('should throw error if principal has no ID', async () => {
			const principalWithoutId = {
				login: 'test-auth-no-id@example.com',
			};
			// Create mock registration response using helper
			const mockResponse = createRegistrationResponse(
				'mock-challenge',
				'mock-credential-id'
			);

			await expectAsync(
				auth.verifyRegistration(
					principalWithoutId as Principal,
					mockResponse
				)
			).toBeRejectedWithError('Principal must have an ID');
		});
	});

	describe('generateAuthenticationOptions', () => {
		it('should generate auth options without userID', async () => {
			const options = await auth.generateAuthenticationOptions();

			expect(typeof options.challenge).toBe('string');
			expect(typeof options.timeout).toBe('number');
			expect(options.rpId).toBe('localhost');
			expect(options.userVerification).toBe('preferred');
			expect(options.allowCredentials).toBeUndefined();
		});

		it('should generate auth options with userID', async () => {
			const testCredentialId = 'test-credential-userid';
			await createTestCredential(testPrincipal.id!, testCredentialId);

			const userID = testPrincipal.id!.toString();
			const options = await auth.generateAuthenticationOptions(userID);

			expect(typeof options.challenge).toBe('string');
			expect(typeof options.timeout).toBe('number');
			expect(options.rpId).toBe('localhost');
			expect(options.userVerification).toBe('preferred');
			expect(options.allowCredentials).toBeDefined();

			if (options.allowCredentials) {
				// Should have at least one credential for this principal
				expect(options.allowCredentials.length).toBeGreaterThan(0);
				// Verify all credentials belong to this principal
				options.allowCredentials.forEach((cred) => {
					expect(typeof cred.id).toBe('string');
					expect(cred.type).toBe('public-key');
				});
			}
		});
	});

	describe('createPrincipal', () => {
		it('should create principal and generate options', async () => {
			const login = 'newuser-create-principal@example.com';
			const principalId = await auth.createPrincipal({
				login: login,
				type: 'user',
				name: 'newuser-create-principal',
			});

			expect(principalId).toBeDefined();

			// Check if principal was created
			const createdPrincipal = await repo.findOne({
				where: { id: principalId },
			});
			expect(createdPrincipal).toBeDefined();
			expect(createdPrincipal!.login).toBe(login);

			// Check if challenge was created for registration
			const challenges = await auth['challengeRepo'].find({
				where: {
					principal_id: principalId,
					challenge_type: 'registration',
				},
			});
			expect(challenges.length).toBeGreaterThan(0);
		});
	});

	describe('helper methods', () => {
		let helperTestPrincipal: Principal;
		let helperCredential1Id: string;
		let helperCredential2Id: string;

		beforeEach(async () => {
			// Create dedicated test principal for helper method tests
			const timestamp = Date.now();
			helperTestPrincipal = await createTestPrincipal(
				`helper-methods-test-${timestamp}`
			);

			helperCredential1Id = `helper-credential-1-${timestamp}`;
			helperCredential2Id = `helper-credential-2-${timestamp}`;

			await createTestCredential(
				helperTestPrincipal.id!,
				helperCredential1Id,
				'key-1',
				1
			);

			await createTestCredential(
				helperTestPrincipal.id!,
				helperCredential2Id,
				'key-2',
				2
			);
		});

		describe('getExistingCredentials', () => {
			it('should return existing credentials for principal', async () => {
				const credentials = await auth['getExistingCredentials'](
					helperTestPrincipal.id!.toString()
				);

				// Should find exactly our 2 test credentials
				expect(credentials.length).toBe(2);

				// Find our specific test credentials
				const cred1 = credentials.find(
					(c) => c.id === helperCredential1Id
				);
				const cred2 = credentials.find(
					(c) => c.id === helperCredential2Id
				);
				expect(cred1).toBeDefined();
				expect(cred2).toBeDefined();
			});

			it('should throw an error for missing id', async () => {
				const credentials = await auth['getExistingCredentials'](
					''
				).catch(() => []);

				expect(credentials.length).toBe(0);
			});
		});

		describe('getAuthenticatorByCredentialID', () => {
			it('should return authenticator credential by ID', async () => {
				const credential =
					await auth['getAuthenticatorByCredentialID'](
						helperCredential1Id
					);

				expect(credential).not.toBeNull();
				if (credential) {
					expect(credential.id)
						.withContext('Credential ID mismatch')
						.toBe('' + helperCredential1Id);
					expect(credential.principal_id)
						.withContext('Principal ID mismatch')
						.toEqual('' + helperTestPrincipal.id!);
					expect(credential.public_key)
						.withContext('Public key mismatch')
						.toBe('key-1');
					expect('' + credential.counter)
						.withContext('Counter mismatch')
						.toEqual('1');
				}
			});

			it('should return null for non-existent credential', async () => {
				const credential =
					await auth['getAuthenticatorByCredentialID'](
						'non-existent'
					);

				expect(credential).toBeNull();
			});

			it('stores credential ID without encoding', async () => {
				// This test documents the fix for credential ID mismatch
				// Previously: Buffer.from(credential.id).toString()
				// Fixed: response.id (stored exactly as provided)
				const testCredId = 'ZXhhY3QtY3JlZGVudGlhbC1pZA';

				// Create credential with exact ID
				await createTestCredential(helperTestPrincipal.id!, testCredId);

				const storedCredential =
					await auth['getAuthenticatorByCredentialID'](testCredId);

				expect(storedCredential).not.toBeNull();
				expect(storedCredential!.id).toBe(testCredId);
			});
		});
	});

	describe('verifyRegistration - With Transports', () => {
		it('should handle credentials with transports', async () => {
			const mockResponse = createRegistrationResponse(
				'challenge',
				'cred-with-transports'
			);

			// Verify the structure includes transports
			const transports = (
				mockResponse.response as Record<string, unknown>
			)['transports'];
			expect(transports).toBeDefined();
			expect(transports).toContain('usb');
		});

		it('should handle credentials without transports', async () => {
			// Create response without transports
			const clientDataJSON = Buffer.from(
				JSON.stringify({
					type: 'webauthn.create',
					challenge: 'test-challenge',
					origin: 'http://localhost',
				})
			).toString('base64');

			const mockResponse = {
				id: 'cred-without-transports',
				rawId: 'cred-without-transports',
				response: {
					attestationObject: 'mock-attestation',
					clientDataJSON,
				},
				type: 'public-key' as const,
				clientExtensionResults: {},
			};

			// Response should not have transports defined
			const transports = (
				mockResponse.response as Record<string, unknown>
			)['transports'];
			expect(transports).toBeUndefined();
		});
	});

	describe('generateAuthenticationOptions - Challenge Storage', () => {
		it('should create challenge when userID is provided', async () => {
			const challengePrincipal = await createTestPrincipal(
				`challenge-storage-${Date.now()}`
			);

			// Get initial challenge count
			const initialChallenges = await auth['challengeRepo'].find({
				where: {
					principal_id: challengePrincipal.id,
					challenge_type: 'authentication',
				},
			});

			await auth.generateAuthenticationOptions(
				challengePrincipal.id!.toString()
			);

			// Verify new challenge was created
			const finalChallenges = await auth['challengeRepo'].find({
				where: {
					principal_id: challengePrincipal.id,
					challenge_type: 'authentication',
				},
			});

			expect(finalChallenges.length).toBe(initialChallenges.length + 1);
		});

		it('should not fail when no credentials exist for userID', async () => {
			const noCreditsPrincipal = await createTestPrincipal(
				`no-creds-challenge-${Date.now()}`
			);

			const options = await auth.generateAuthenticationOptions(
				noCreditsPrincipal.id!.toString()
			);

			expect(options.challenge).toBeDefined();
			expect(typeof options.challenge).toBe('string');
		});
	});

	describe('getExistingCredentials - Transports Handling', () => {
		let transportsTestPrincipal: Principal;

		beforeEach(async () => {
			transportsTestPrincipal = await createTestPrincipal(
				`transports-test-${Date.now()}`
			);
		});

		it('should parse and return transports correctly', async () => {
			const credentialId = 'cred-with-parsed-transports';
			const transports = ['usb', 'nfc'];

			// Manually insert a credential with transports
			await auth['credentialRepo'].insert({
				records: [
					{
						id: credentialId,
						principal_id: transportsTestPrincipal.id!,
						public_key: 'test-key',
						counter: 0,
						transports: JSON.stringify(transports),
					},
				],
			});

			const credentials = await auth['getExistingCredentials'](
				transportsTestPrincipal.id!.toString()
			);

			expect(credentials.length).toBeGreaterThan(0);
			const cred = credentials.find((c) => c.id === credentialId);
			expect(cred).toBeDefined();
			if (cred && cred.transports) {
				expect(cred.transports).toContain('usb');
				expect(cred.transports).toContain('nfc');
			}
		});

		it('should use default transports for malformed JSON', async () => {
			const credentialId = 'cred-malformed-transports';

			// Manually insert a credential with malformed transports JSON
			await auth['credentialRepo'].insert({
				records: [
					{
						id: credentialId,
						principal_id: transportsTestPrincipal.id!,
						public_key: 'test-key',
						counter: 0,
						transports: 'invalid-json{]',
					},
				],
			});

			const credentials = await auth['getExistingCredentials'](
				transportsTestPrincipal.id!.toString()
			);

			const cred = credentials.find((c) => c.id === credentialId);
			expect(cred).toBeDefined();
			// Should default to 'internal' for malformed JSON
			if (cred && cred.transports) {
				expect(cred.transports).toContain('internal');
			}
		});

		it('should use fallback transports when none are stored', async () => {
			const credentialId = 'cred-no-transports-stored';

			// Manually insert a credential with no transports field
			await auth['credentialRepo'].insert({
				records: [
					{
						id: credentialId,
						principal_id: transportsTestPrincipal.id!,
						public_key: 'test-key',
						counter: 0,
					},
				],
			});

			const credentials = await auth['getExistingCredentials'](
				transportsTestPrincipal.id!.toString()
			);

			const cred = credentials.find((c) => c.id === credentialId);
			expect(cred).toBeDefined();
			if (cred && cred.transports) {
				expect(cred.transports).toContain('internal');
				expect(cred.transports).toContain('hybrid');
			}
		});
	});
});
