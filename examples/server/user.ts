import { Principal } from '@riao/iam';
import { QueryRepository } from '@riao/dbal';

/**
 * User interface extending Principal
 */
export type User = Principal;

/**
 * Request interfaces
 */
export interface RegistrationRequest {
	login: string;
	name: string;
}

export interface AuthenticationRequest {
	login?: string;
}

/**
 * Helper function to find or create user
 */
export async function findOrCreateUser(
	userRepo: QueryRepository<User>,
	user: Partial<User>
): Promise<User> {
	let record = await userRepo.findOne({ where: { login: user.login } });

	if (!record) {
		const { id } = await userRepo.insertOne({
			record: {
				login: user.login,
				name: user.name || user.login,
				type: 'user',
			},
		});

		record = await userRepo.findById(id!);
	}

	return record!;
}
