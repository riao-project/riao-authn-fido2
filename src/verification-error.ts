/**
 * SimpleWebAuthn 13 uses plain Errors for assertion validation. Match only its
 * known validation messages, never arbitrary exceptions from crypto or storage.
 */
export function isAuthenticationVerificationError(error: unknown): boolean {
	if (!(error instanceof Error)) {
		return false;
	}

	const messages = [
		/^Missing credential ID$/,
		/^Credential ID was not base64url-encoded$/,
		/^Unexpected credential type .+, expected "public-key"$/,
		/^Credential missing response$/,
		/^Credential response clientDataJSON was not a string$/,
		/^Unexpected authentication response type: .+$/,
		/^Unexpected authentication response challenge ".*", expected ".*"$/,
		/^Unexpected authentication response origin ".*", expected ".*"$/,
		/^Credential response authenticatorData was not a base64url string$/,
		/^Credential response signature was not a base64url string$/,
		/^Credential response userHandle was not a string$/,
		/^ClientDataJSON tokenBinding was not an object$/,
		/^Unexpected tokenBinding status .+$/,
		/^Authenticator data was \d+ bytes, expected at least 37 bytes$/,
		/^Leftover bytes detected while parsing authenticator data$/,
		/^User not present during authentication$/,
		/^User verification required, but user could not be verified$/,
		/^Response counter value \d+ was lower than expected \d+$/,
		/^Invalid signature component length \d+, expected \d+$/,
		/^Data does not match to ECDSASigValue ASN1 schema\.(?: .*)?$/,
	];

	return (
		messages.some((pattern) => pattern.test(error.message)) ||
		(error.name === 'UnexpectedRPIDHash' &&
			error.message === 'Unexpected RP ID hash') ||
		(error.name === 'InvalidBackupFlags' &&
			error.message ===
				'Single-device credential indicated that it was backed up, ' +
					'which should be impossible.')
	);
}

export function hasValidClientDataJSON(data: unknown): boolean {
	if (typeof data !== 'string' || !/^[A-Za-z0-9_-]+={0,2}$/.test(data)) {
		return false;
	}
	try {
		const parsed: unknown = JSON.parse(
			Buffer.from(data, 'base64url').toString('utf8')
		);

		return typeof parsed === 'object' && parsed !== null;
	}
	catch (error) {
		if (error instanceof SyntaxError) {
			return false;
		}

		throw error;
	}
}
