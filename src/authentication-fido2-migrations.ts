import { Migration } from '@riao/dbal';
import { AuthMigrations } from '@riao/iam/auth/auth-migrations';

import {
	CreateFido2ChallengesTableMigration,
	CreateFido2CredentialsTableMigration,
} from './migrations';

export class AuthenticationFido2Migrations extends AuthMigrations {
	override package = '@riao/authn-fido2';
	override name = '@riao/authn-fido2';

	override async getMigrations(): Promise<
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		Record<string, typeof Migration<any>>
		> {
		return {
			...(await super.getMigrations()),
			'create-fido2-credentials-table':
				CreateFido2CredentialsTableMigration,
			'create-fido2-challenges-table':
				CreateFido2ChallengesTableMigration,
		};
	}
}
