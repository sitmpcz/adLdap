<?php
namespace adLDAP;

use Exception;

/**
 * adLDAP Exception Handler
 *
 * Exceptions of this type are thrown on bind failure or when SSL is required but not configured
 * Example:
 * try {
 *   $adldap = new adLDAP();
 * }
 * catch (adLDAPException $e) {
 *   echo $e;
 *   exit();
 * }
 */
class adLDAPException extends Exception
{
}
