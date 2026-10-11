import { ColumnType, Migration } from '@riao/dbal';

export class AddChallengeConsumptionId extends Migration {
	override async up(): Promise<void> {
		await this.ddl.addColumns({
			table: 'iam_fido2_challenges',
			columns: [{
				name: 'consumption_id', type: ColumnType.VARCHAR, length: 64,
			}],
		});
	}

	override async down(): Promise<void> {
		await this.ddl.dropColumn({
			table: 'iam_fido2_challenges', column: 'consumption_id',
		});
	}
}
