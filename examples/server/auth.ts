import { Fido2Authentication } from '../../src/authentication-fido2';
import { User } from './user';

/**
 * Extended FIDO2 Authentication class with custom user support
 */
export class Auth extends Fido2Authentication<User> {}
