import {
	Database,
	DatabaseConnectionOptions,
	Migration,
	MigrationRunner,
	MigrationPackage,
} from '@riao/dbal';
import { maindb } from '../database/main';
import { DatabasePostgres18 } from '@riao/postgres';

export function createDatabase(name: string): Database {
	return new (class extends DatabasePostgres18 {
		override name = name;

		override async init(options?: {
			connectionOptions?: DatabaseConnectionOptions;
			useSchemaCache?: boolean;
		}): Promise<void> {
			await maindb.ddl.dropDatabase({
				ifExists: true,
				name: `"${name}"`,
			});
			await maindb.ddl.createDatabase({
				name: `"${name}"`,
			});

			await super.init(options);
		}

		public override configureFromEnv(): void {
			this.env = {
				NODE_ENV: 'test',
				host: maindb.env.host,
				port: maindb.env.port,
				username: maindb.env.username,
				password: maindb.env.password,
				database: name,
			};
		}
	})();
}

export async function getMigrations(
	db: Database,
	migrationPack: MigrationPackage
) {
	const migrationsRecord = await migrationPack.getMigrations();

	return Object.entries(migrationsRecord).reduce(
		(acc, [key, MigrationClass]) => {
			acc[key] = new (MigrationClass as typeof Migration)(db);
			return acc;
		},
		{} as Record<string, Migration>
	);
}

export async function runMigrations(
	db: Database,
	migrationPack: MigrationPackage
) {
	const runner = new MigrationRunner(db);
	const migrations = await getMigrations(db, migrationPack);

	return runner.run(migrations);
}

export async function runMigrationsDown(
	db: Database,
	migrationPack: MigrationPackage
) {
	const runner = new MigrationRunner(db);
	const migrations = await getMigrations(db, migrationPack);

	await runner.run(
		migrations,
		undefined,
		'down',
		Object.keys(migrations).length
	);
}

export let db: Database;

export async function initTestDatabase() {
	db = createDatabase('authn-passwordtest-db');
	await db.init();
}
