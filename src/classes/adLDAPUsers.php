<?php
namespace adLDAP;

//use http\Params;

/**
 * PHP LDAP CLASS FOR MANIPULATING ACTIVE DIRECTORY
 * Version 4.0.4
 *
 * PHP Version 5 with SSL and LDAP support
 *
 * Written by Scott Barnett, Richard Hyland
 *   email: scott@wiggumworld.com, adldap@richardhyland.com
 *   http://adldap.sourceforge.net/
 *
 * Copyright (c) 2006-2012 Scott Barnett, Richard Hyland
 *
 * We'd appreciate any improvements or additions to be submitted back
 * to benefit the entire community :)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * @category ToolsAndUtilities
 * @package adLDAP
 * @subpackage User
 * @author Scott Barnett, Richard Hyland
 * @copyright (c) 2006-2012 Scott Barnett, Richard Hyland
 * @license http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html LGPLv2.1
 * @revision $Revision: 97 $
 * @version 4.0.4
 * @link http://adldap.sourceforge.net/
 */
require_once(dirname(__FILE__) . '/../adLDAP.php');
require_once(dirname(__FILE__) . '/../collections/adLDAPUserCollection.php');

/**
 * USER FUNCTIONS
 */
class adLDAPUsers
{
    /**
     * The current adLDAP connection via dependency injection
     *
     * @var adLDAP
     */
    protected adLDAP $adldap;

    public function __construct(adLDAP $adldap)
    {
        $this->adldap = $adldap;
    }

    /**
     * Validate a user's login credentials
     *
     * @param string $username A user's AD username
     * @param string $password A user's AD password
     * @param bool $preventRebind
     * @return bool
     * @throws adLDAPException
     */
    public function authenticate(string $username,string  $password,bool $preventRebind = false): bool
    {
        return $this->adldap->authenticate($username, $password, $preventRebind);
    }

    /**
     * Create a user
     *
     * If you specify a password here, this can only be performed over SSL
     *
     * @param array $attributes The attributes to set to the user account
     * @return bool
     * @throws adLDAPException
     */
    public function create(array $attributes): bool
    {
        // Check for compulsory fields
        if (!array_key_exists("username", $attributes)) {
            return "Missing compulsory field [username]";
        }
        if (!array_key_exists("firstname", $attributes)) {
            return "Missing compulsory field [firstname]";
        }
        if (!array_key_exists("surname", $attributes)) {
            return "Missing compulsory field [surname]";
        }
        if (!array_key_exists("email", $attributes)) {
            return "Missing compulsory field [email]";
        }
        if (!array_key_exists("container", $attributes)) {
            return "Missing compulsory field [container]";
        }
        if (!is_array($attributes["container"])) {
            return "Container attribute must be an array.";
        }

        if (array_key_exists("password", $attributes) && (!$this->adldap->getUseSSL() && !$this->adldap->getUseTLS())) {
            throw new adLDAPException('SSL must be configured on your webserver and enabled in the class to set passwords.');
        }

        if (!array_key_exists("display_name", $attributes)) {
            $attributes["display_name"] = $attributes["firstname"] . " " . $attributes["surname"];
        }

        // Translate the schema
        $add = $this->adldap->adldap_schema($attributes);

        // Additional stuff only used for adding accounts
        $add["cn"][0] = $attributes["display_name"];
        $add["samaccountname"][0] = $attributes["username"];
        $add["objectclass"][0] = "top";
        $add["objectclass"][1] = "person";
        $add["objectclass"][2] = "organizationalPerson";
        $add["objectclass"][3] = "user"; //person?
        //$add["name"][0]=$attributes["firstname"]." ".$attributes["surname"];

        // Set the account control attribute
        $control_options = array("NORMAL_ACCOUNT");
        if (!$attributes["enabled"]) {
            $control_options[] = "ACCOUNTDISABLE";
        }
        $add["userAccountControl"][0] = $this->accountControl($control_options);

        // Determine the container
        $attributes["container"] = array_reverse($attributes["container"]);
        $container = "OU=" . implode(", OU=", $attributes["container"]);

        // Add the entry
        $result = @ldap_add($this->adldap->getLdapConnection(), "CN=" . $add["cn"][0] . ", " . $container . "," . $this->adldap->getBaseDn(), $add);
        if (!$result) {
            return false;
        }

        return true;
    }

    /**
     * Account control options
     *
     * @param array $options The options to convert to int
     * @return int
     */
    protected function accountControl(array $options): int
    {
        $val = 0;

        if (is_array($options)) {
            if (in_array("SCRIPT", $options)) {
                $val = $val + 1;
            }
            if (in_array("ACCOUNTDISABLE", $options)) {
                $val = $val + 2;
            }
            if (in_array("HOMEDIR_REQUIRED", $options)) {
                $val = $val + 8;
            }
            if (in_array("LOCKOUT", $options)) {
                $val = $val + 16;
            }
            if (in_array("PASSWD_NOTREQD", $options)) {
                $val = $val + 32;
            }
            //PASSWD_CANT_CHANGE Note You cannot assign this permission by directly modifying the UserAccountControl attribute.
            //For information about how to set the permission programmatically, see the "Property flag descriptions" section.
            if (in_array("ENCRYPTED_TEXT_PWD_ALLOWED", $options)) {
                $val = $val + 128;
            }
            if (in_array("TEMP_DUPLICATE_ACCOUNT", $options)) {
                $val = $val + 256;
            }
            if (in_array("NORMAL_ACCOUNT", $options)) {
                $val = $val + 512;
            }
            if (in_array("INTERDOMAIN_TRUST_ACCOUNT", $options)) {
                $val = $val + 2048;
            }
            if (in_array("WORKSTATION_TRUST_ACCOUNT", $options)) {
                $val = $val + 4096;
            }
            if (in_array("SERVER_TRUST_ACCOUNT", $options)) {
                $val = $val + 8192;
            }
            if (in_array("DONT_EXPIRE_PASSWORD", $options)) {
                $val = $val + 65536;
            }
            if (in_array("MNS_LOGON_ACCOUNT", $options)) {
                $val = $val + 131072;
            }
            if (in_array("SMARTCARD_REQUIRED", $options)) {
                $val = $val + 262144;
            }
            if (in_array("TRUSTED_FOR_DELEGATION", $options)) {
                $val = $val + 524288;
            }
            if (in_array("NOT_DELEGATED", $options)) {
                $val = $val + 1048576;
            }
            if (in_array("USE_DES_KEY_ONLY", $options)) {
                $val = $val + 2097152;
            }
            if (in_array("DONT_REQ_PREAUTH", $options)) {
                $val = $val + 4194304;
            }
            if (in_array("PASSWORD_EXPIRED", $options)) {
                $val = $val + 8388608;
            }
            if (in_array("TRUSTED_TO_AUTH_FOR_DELEGATION", $options)) {
                $val = $val + 16777216;
            }
        }
        return $val;
    }

    /**
     * Delete a user account
     *
     * @param string $username The username to delete (please be careful here!)
     * @param bool $isGUID Is the username a GUID or a samAccountName
     * @return bool
     */
    public function delete(string $username,bool $isGUID = false): bool
    {
        if ($userinfo = $this->info($username, array("*"), $isGUID)) {
            $dn = $userinfo[0]['distinguishedname'][0];
            $result = $this->adldap->folder()->delete($dn);
            if (!$result) {
                return false;
            }
            return true;
        }
        return false;
    }

    /**
     * Groups the user is a member of
     *
     * @param null|string $username The username to query
     * @param bool $recursive Recursive list of groups
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return array|false
     */
    public function groups(?string $username,?bool $recursive = NULL,bool $isGUID = false): array|false
    {
        if ($username === NULL) {
            return false;
        }
        if ($recursive === NULL) {
            $recursive = $this->adldap->getRecursiveGroups();
        } // Use the default option if they haven't set it
        if (!$this->adldap->getLdapBind()) {
            return false;
        }

        // Search the directory for their information
        $info = @$this->info($username, array("memberof", "primarygroupid"), $isGUID);
        // PHP Warning: Trying to access array offset on value of type bool in
        if (($info) && isset($info[0]) && isset($info[0]["memberof"])) {
            $groups = $this->adldap->utilities()->niceNames($info[0]["memberof"]); // Presuming the entry returned is our guy (unique usernames)
        } else {
            $groups = array();
        }

        if ($recursive === true) {
            foreach ($groups as $id => $groupName) {
                $extraGroups = $this->adldap->group()->recursiveGroups($groupName);
                $groups = array_merge($groups, $extraGroups);
            }
        }

        return $groups;
    }

    /**
     * Find information about the users. Returned in a raw array format from AD
     *
     * @param null|string $username The username to query
     * @param null|array $fields Array of parameters to query
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return array|false
     */
    public function info(?string $username,?array $fields = NULL,bool $isGUID = false): array|false
    {
        if ($username === NULL) {
            return false;
        }
        if (!$this->adldap->getLdapBind()) {
            return false;
        }

        if ($isGUID === true) {
            $username = $this->adldap->utilities()->strGuidToHex($username);
            $filter = "objectguid=" . $username;
        } else if (str_contains($username, "@")) {
            $filter = "userPrincipalName=" . $username;
        } else {
            $filter = "samaccountname=" . $username;
        }
        $filter = "(&(objectCategory=person)({$filter}))";
        if ($fields === NULL) {
            $fields = array("samaccountname", "mail", "memberof", "department", "displayname", "telephonenumber", "primarygroupid", "objectsid");
        }
        if (!in_array("objectsid", $fields)) {
            $fields[] = "objectsid";
        }
        if ($sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields)) {
            $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

            if (isset($entries[0])) {
                if ($entries[0]['count'] >= 1) {
                    if (in_array("memberof", $fields)) {
                        // AD does not return the primary group in the ldap query, we may need to fudge it
                        if ($this->adldap->getRealPrimaryGroup() && isset($entries[0]["primarygroupid"][0]) && isset($entries[0]["objectsid"][0])) {
                            //$entries[0]["memberof"][]=$this->group_cn($entries[0]["primarygroupid"][0]);
                            $entries[0]["memberof"][] = $this->adldap->group()->getPrimaryGroup($entries[0]["primarygroupid"][0], $entries[0]["objectsid"][0]);
                        } else {
                            $entries[0]["memberof"][] = "CN=Domain Users,CN=Users," . $this->adldap->getBaseDn();
                        }
                        if (!isset($entries[0]["memberof"]["count"])) {
                            $entries[0]["memberof"]["count"] = 0;
                        }
                        $entries[0]["memberof"]["count"]++;
                    }
                }
                return $entries;
            }
        }
        return false;
    }

    /**
     * Find information about the users. Returned in a raw array format from AD
     *
     * @param null|string $username The username to query
     * @param null|array $fields Array of parameters to query
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return false|adLDAPUserCollection
     */
    public function infoCollection(?string $username,?array $fields = NULL,bool $isGUID = false): false|adLDAPUserCollection
    {
        if ($username === NULL) {
            return false;
        }
        if (!$this->adldap->getLdapBind()) {
            return false;
        }

        $info = $this->info($username, $fields, $isGUID);

        if ($info !== false) {
            $collection = new adLDAPUserCollection($info, $this->adldap);
            return $collection;
        }
        return false;
    }

    /**
     * Determine if a user is in a specific group
     *
     * @param null|string $username The username to query
     * @param null|string $group The name of the group to check against
     * @param bool $recursive Check groups recursively
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return bool
     */
    public function inGroup(?string $username,?string $group,?bool $recursive = NULL,bool $isGUID = false): bool
    {
        if ($username === NULL) {
            return false;
        }
        if ($group === NULL) {
            return false;
        }
        if (!$this->adldap->getLdapBind()) {
            return false;
        }
        if ($recursive === NULL) {
            $recursive = $this->adldap->getRecursiveGroups();
        } // Use the default option if they haven't set it

        // Get a list of the groups
        $groups = $this->groups($username, $recursive, $isGUID);

        // Return true if the specified group is in the group list
        if (in_array($group, $groups)) {
            return true;
        }

        return false;
    }

    /**
     * Determine a user's password expiry date
     *
     * @param null|string $username The username to query
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return array|string|false
     * @throws adLDAPException
     * @requires bcmath http://www.php.net/manual/en/book.bc.php
     */
    public function passwordExpiry(?string $username,bool $isGUID = false): array|string|false
    {
        if ($username === NULL) {
            throw new adLDAPException("Missing compulsory field [username]");
        }
        if (!$this->adldap->getLdapBind()) {
            return false;
        }
        if (!function_exists('bcmod')) {
            throw new adLDAPException("Missing function support [bcmod] https://www.php.net/manual/en/book.bc.php");
        }

        $userInfo = $this->info($username, array("pwdlastset", "useraccountcontrol"), $isGUID);
        if (!$userInfo) return false;
        $pwdLastSet = $userInfo[0]['pwdlastset'][0];
        $status = array();

        if ($userInfo[0]['useraccountcontrol'][0] == '66048') {
            // Password does not expire
            return "Does not expire";
        }
        if ($pwdLastSet === '0') {
            // Password has already expired
            return "Password has expired";
        }

        // Password expiry in AD can be calculated from TWO values:
        //   - User's own pwdLastSet attribute: stores the last time the password was changed
        //   - Domain's maxPwdAge attribute: how long passwords last in the domain
        //
        // Although Microsoft chose to use a different base and unit for time measurements.
        // This function will convert them to Unix timestamps
        $sr = ldap_read($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), 'objectclass=*', array('maxPwdAge'));
        if (!$sr) {
            return false;
        }
        $info = ldap_get_entries($this->adldap->getLdapConnection(), $sr);
        $maxPwdAge = $info[0]['maxpwdage'][0];


        // See MSDN: http://msdn.microsoft.com/en-us/library/ms974598.aspx
        //
        // pwdLastSet contains the number of 100 nanosecond intervals since January 1, 1601 (UTC),
        // stored in a 64 bit integer.
        //
        // The number of seconds between this date and Unix epoch is 11644473600.
        //
        // maxPwdAge is stored as a large integer that represents the number of 100 nanosecond
        // intervals from the time the password was set before the password expires.
        //
        // We also need to scale this to seconds but also this value is a _negative_ quantity!
        //
        // If the low 32 bits of maxPwdAge are equal to 0 passwords do not expire
        //
        // Unfortunately the maths involved are too big for PHP integers, so I've had to require
        // BCMath functions to work with arbitrary precision numbers.
        if (bcmod($maxPwdAge, 4294967296) === '0') {
            return "Domain does not expire passwords";
        }

        // Add maxpwdage and pwdlastset and we get password expiration time in Microsoft's
        // time units.  Because maxpwd age is negative we need to subtract it.
        $pwdExpire = bcsub($pwdLastSet, $maxPwdAge);

        // Convert MS's time to Unix time
        $status['expiryts'] = bcsub(bcdiv($pwdExpire, '10000000'), '11644473600');
        $status['expiryformat'] = date('Y-m-d H:i:s', bcsub(bcdiv($pwdExpire, '10000000'), '11644473600'));

        return $status;
    }

    /**
     * Modify a user
     *
     * @param null|string $username The username to query
     * @param array $attributes The attributes to modify.  Note if you set the enabled attribute you must not specify any other attributes
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return bool
     * @throws adLDAPException
     */
    public function modify(?string $username,array $attributes,bool $isGUID = false): bool
    {
        if ($username === NULL) {
            throw new adLDAPException("Missing compulsory field [username]");
        }
        if (array_key_exists("password", $attributes) && !$this->adldap->getUseSSL() && !$this->adldap->getUseTLS()) {
            throw new adLDAPException('SSL/TLS must be configured on your webserver and enabled in the class to set passwords.');
        }

        // Find the dn of the user
        $userDn = $this->dn($username, $isGUID);
        if ($userDn === false) {
            return false;
        }

        // Translate the update to the LDAP schema                
        $mod = $this->adldap->adldap_schema($attributes);

        // Check to see if this is an enabled status update
        if (!$mod && !array_key_exists("enabled", $attributes)) {
            return false;
        }
        // Set the account control attribute (only if specified)
        if (array_key_exists("enabled", $attributes)) {
            if ($attributes["enabled"]) {
                $controlOptions = array("NORMAL_ACCOUNT");
            } else {
                $controlOptions = array("NORMAL_ACCOUNT", "ACCOUNTDISABLE");
            }
            $mod["userAccountControl"][0] = $this->accountControl($controlOptions);
        }

        // Do the update
        $result = @ldap_modify($this->adldap->getLdapConnection(), $userDn, $mod);

        if (!$result) {
            // homola - zpracuj chybu
            ldap_get_option($this->adldap->getLdapConnection(), LDAP_OPT_DIAGNOSTIC_MESSAGE, $err);
            throw new adLDAPException(sprintf('%s (%s)', ldap_error($this->adldap->getLdapConnection()), $err));
            //return false; 
        }

        return true;
    }

    /**
     * Disable a user account
     *
     * @param null|string $username The username to disable
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return bool
     * @throws adLDAPException
     */
    public function disable(?string $username,bool $isGUID = false): bool
    {
        if ($username === NULL) {
            throw new adLDAPException("Missing compulsory field [username]");
        }
        $attributes = array("enabled" => 0);
        $result = $this->modify($username, $attributes, $isGUID);
        if (!$result) {
            return false;
        }

        return true;
    }

    /**
     * Enable a user account
     *
     * @param null|string $username The username to enable
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return bool
     * @throws adLDAPException
     */
    public function enable(?string $username,bool $isGUID = false): bool
    {
        if ($username === NULL) {
            throw new adLDAPException("Missing compulsory field [username]");
        }
        $attributes = array("enabled" => 1);
        $result = $this->modify($username, $attributes, $isGUID);
        if (!$result) {
            return false;
        }

        return true;
    }

    /**
     * Set the password of a user - This must be performed over SSL
     *
     * @param null|string $username The username to modify
     * @param null|string $password The new password
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return bool
     * @throws adLDAPException
     */
    public function password(?string $username,?string $password,bool $isGUID = false): bool
    {
        if ($username === NULL) {
            throw new adLDAPException("Missing username");
        }
        if ($password === NULL) {
            throw new adLDAPException("Missing password");
        }
        if (!$this->adldap->getLdapBind()) {
            return false;
        }
        if (!$this->adldap->getUseSSL() && !$this->adldap->getUseTLS()) {
            throw new adLDAPException('SSL must be configured on your webserver and enabled in the class to set passwords.');
        }

        $userDn = $this->dn($username, $isGUID);
        if ($userDn === false) {
            return false;
        }

        $add = array();
        $add["unicodePwd"][0] = $this->encodePassword($password);

        $result = @ldap_mod_replace($this->adldap->getLdapConnection(), $userDn, $add);
        if ($result === false) {
            $err = ldap_errno($this->adldap->getLdapConnection());
            if ($err) {
                $msg = 'Error ' . $err . ': ' . ldap_err2str($err) . '.';
                if ($err == 53) {
                    $msg .= ' Your password might not match the password policy.';
                }
                throw new adLDAPException($msg);
            } else {
                return false;
            }
        }

        return true;
    }

    /**
     * Encode a password for transmission over LDAP
     *
     * @param string $password The password to encode
     * @return string
     */
    public function encodePassword(string $password): string
    {
        $password = "\"" . $password . "\"";
        // homola - upravil protoze tohle spatne encodovalo ceske znaky proTĂ©bĂ©L+20 Traktor+1Ä›ĹˇÄŤĹ™ĹľĂ˝
        if (function_exists("mb_convert_encoding")) {
            $encoded = mb_convert_encoding($password, "UTF-16LE");
        } else {
            $encoded = "";
            for ($i = 0; $i < strlen($password); $i++) {
                //$encoded.="{$password{$i}}\000";
                // prechod na PHP 7.4
                $encoded .= "{$password[$i]}\000";
            }
        }
        return $encoded;
    }

    /**
     * Obtain the user's distinguished name based on their userid
     *
     *
     * @param string $username The username
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return string|false
     */
    public function dn(string $username,bool $isGUID = false): string|false
    {
        $user = $this->info($username, array("cn"), $isGUID);
        if (($user) && ($user[0]["dn"] !== NULL)) {
            $userDn = $user[0]["dn"];
            return $userDn;
        }
        return false;
    }

    /**
     * Return a list of all users in AD
     *
     * @param bool $includeDescription Return a description of the user
     * @param string $search Search parameter
     * @param bool $sorted Sort the user accounts
     * @return array|false
     */
    public function all(bool $includeDescription = false,string $search = "*",bool $sorted = true): array|false
    {
        if (!$this->adldap->getLdapBind()) {
            return false;
        }

        // Perform the search and grab all their details
        $filter = "(&(objectClass=user)(samaccounttype=" . adLDAP::ADLDAP_NORMAL_ACCOUNT . ")(objectCategory=person)(cn=" . $search . "))";
        $fields = array("samaccountname", "displayname");
        if ($sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields))
        {
        $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

        $usersArray = array();
        for ($i = 0; $i < $entries["count"]; $i++) {
            if ($includeDescription && strlen($entries[$i]["displayname"][0]) > 0) {
                $usersArray[$entries[$i]["samaccountname"][0]] = $entries[$i]["displayname"][0];
            } elseif ($includeDescription) {
                $usersArray[$entries[$i]["samaccountname"][0]] = $entries[$i]["samaccountname"][0];
            } else {
                array_push($usersArray, $entries[$i]["samaccountname"][0]);
            }
        }
        if ($sorted) {
            asort($usersArray);
        }
        return $usersArray;
        } else {
            return false;
        }
    }

    /**
     * Converts a username (samAccountName) to a GUID
     *
     * @param null|string $username The username to query
     * @return string|false
     * @throws adLDAPException
     */
    public function usernameToGuid(?string $username): string|false
    {
        if (!$this->adldap->getLdapBind()) {
            return false;
        }
        if ($username === null) {
            throw new adLDAPException( "Missing compulsory field [username]");
        }

        $filter = "samaccountname=" . $username;
        $fields = array("objectGUID");
        if ($sr = @ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields)) {
            if (ldap_count_entries($this->adldap->getLdapConnection(), $sr) > 0) {
                $entry = @ldap_first_entry($this->adldap->getLdapConnection(), $sr);
                $guid = @ldap_get_values_len($this->adldap->getLdapConnection(), $entry, 'objectGUID');
                $strGUID = $this->adldap->utilities()->binaryToText($guid[0]);
                return $strGUID;
            }
        }
        return false;
    }

    /**
     * Return a list of all users in AD that have a specific value in a field
     *
     * @param bool $includeDescription Return a description of the user
     * @param string|false|null $searchField Field to search search for
     * @param string|false|null $searchFilter Value to search for in the specified field
     * @param bool $sorted Sort the user accounts
     * @return array|false
     */
    public function find(bool $includeDescription = false,string|false|null $searchField = null,string|false|null $searchFilter = null,bool $sorted = true): array|false
    {
        if (!$this->adldap->getLdapBind()) {
            return false;
        }

        // Perform the search and grab all their details
        $searchParams = "";
        if (($searchField) and ($searchFilter)) {
            $searchParams = "(" . $searchField . "=" . $searchFilter . ")";
        }
        $filter = "(&(objectClass=user)(samaccounttype=" . adLDAP::ADLDAP_NORMAL_ACCOUNT . ")(objectCategory=person)" . $searchParams . ")";
        $fields = array("samaccountname", "displayname");
        if ($sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields))
        {
        $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

        $usersArray = array();
        for ($i = 0; $i < $entries["count"]; $i++) {
            if ($includeDescription && strlen($entries[$i]["displayname"][0]) > 0) {
                $usersArray[$entries[$i]["samaccountname"][0]] = $entries[$i]["displayname"][0];
            } else if ($includeDescription) {
                $usersArray[$entries[$i]["samaccountname"][0]] = $entries[$i]["samaccountname"][0];
            } else {
                array_push($usersArray, $entries[$i]["samaccountname"][0]);
            }
        }
        if ($sorted) {
            asort($usersArray);
        }
        return ($usersArray);
        } else {
            return false;
        }
    }

    /**
     * Move a user account to a different OU
     *
     * @param null|string $username The username to move (please be careful here!)
     * @param null|array $container The container or containers to move the user to (please be careful here!).
     * accepts containers in 1. parent 2. child order
     * @return bool
     * @throws adLDAPException
     */
    public function move(?string $username,?array $container): bool
    {
        if (!$this->adldap->getLdapBind()) {
            return false;
        }
        if ($username === null) {
            throw new adLDAPException("Missing compulsory field [username]");
        }
        if ($container === null) {
            throw new adLDAPException( "Missing compulsory field [container]");
        }
        if (!is_array($container)) {
            throw new adLDAPException( "Container must be an array");
        }

        if ($userInfo = $this->info($username, array("*"))) {
            $dn = $userInfo[0]['distinguishedname'][0];
            $newRDn = "cn=" . $username;
            $container = array_reverse($container);
            $newContainer = "ou=" . implode(",ou=", $container);
            $newBaseDn = strtolower($newContainer) . "," . $this->adldap->getBaseDn();
            $result = @ldap_rename($this->adldap->getLdapConnection(), $dn, $newRDn, $newBaseDn, true);
            if ($result !== true) {
                return false;
            }
            return true;
        }
        return false;
    }

    /**
     * Rename a user account - change SN
     * homola SITmP - added
     * @param null|string $olddn - distinguished name to change
     * @param null|string $newcn - new cn
     * @return bool
     * @throws adLDAPException
     */
    public function rename(?string $olddn,?string $newcn): bool
    {
        if (!$this->adldap->getLdapBind()) {
            return false;
        }
        if ($olddn === null) {
            throw new adLDAPException( "Missing compulsory field [olddn]");
        }
        if ($newcn === null) {
            throw new adLDAPException( "Missing compulsory field [newcn]");
        }
        $newRDn = "cn=" . $newcn;
        $result = @ldap_rename($this->adldap->getLdapConnection(), $olddn, $newRDn, NULL, true);
        if ($result !== true) {
            return false;
        }
        return true;
    }

    /**
     * Get the last logon time of any user as a Unix timestamp
     * An integer data type is a non-decimal number between -2147483648 and 2147483647 in 32 bit systems, and between -9223372036854775808 and 9223372036854775807 in 64 bit systems. A value greater (or lower) than this, will be stored as float, because it exceeds the limit of an integer.
     *
     * @param null|string $username
     * @return false|int  $unixTimestamp
     * @throws adLDAPException
     */
    public function getLastLogon(?string $username): int|false
    {
        if (!$this->adldap->getLdapBind()) {
            return false;
        }
        if ($username === null) {
            throw new adLDAPException( "Missing compulsory field [username]");
        }
        if ($userInfo = $this->info($username, array("lastLogonTimestamp"))) {
            $lastLogon = adLDAPUtils::convertWindowsTimeToUnixTime($userInfo[0]['lastLogonTimestamp'][0]);
            return $lastLogon;
        }
        return false;
    }

}
