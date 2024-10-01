<?php

namespace adLDAP;

use LDAP;

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
 * @author Scott Barnett, Richard Hyland
 * @copyright (c) 2006-2012 Scott Barnett, Richard Hyland
 * @license http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html LGPLv2.1
 * @revision $Revision: 169 $
 * @version 4.0.4
 * @link http://adldap.sourceforge.net/
 */

/**
 * Main adLDAP class
 *
 * Can be initialised using $adldap = new adLDAP();
 *
 * Something to keep in mind is that Active Directory is a permissions
 * based directory. If you bind as a domain user, you can't fetch as
 * much information on other users as you could as a domain admin.
 *
 * Before asking questions, please read the Documentation at
 * http://adldap.sourceforge.net/wiki/doku.php?id=api
 */
require_once(dirname(__FILE__) . '/collections/adLDAPCollection.php');
require_once(dirname(__FILE__) . '/classes/adLDAPGroups.php');
require_once(dirname(__FILE__) . '/classes/adLDAPUsers.php');
require_once(dirname(__FILE__) . '/classes/adLDAPFolders.php');
require_once(dirname(__FILE__) . '/classes/adLDAPUtils.php');
require_once(dirname(__FILE__) . '/classes/adLDAPContacts.php');
require_once(dirname(__FILE__) . '/classes/adLDAPExchange.php');
require_once(dirname(__FILE__) . '/classes/adLDAPComputers.php');
require_once(dirname(__FILE__) . '/adLDAPException.php');


class adLDAP
{

    /**
     * Define the different types of account in AD
     */
    const ADLDAP_NORMAL_ACCOUNT = 805306368;
    const ADLDAP_WORKSTATION_TRUST = 805306369;
    const ADLDAP_INTERDOMAIN_TRUST = 805306370;
    const ADLDAP_SECURITY_GLOBAL_GROUP = 268435456;
    const ADLDAP_DISTRIBUTION_GROUP = 268435457;
    const ADLDAP_SECURITY_LOCAL_GROUP = 536870912;
    const ADLDAP_DISTRIBUTION_LOCAL_GROUP = 536870913;
    const ADLDAP_FOLDER = 'OU';
    const ADLDAP_CONTAINER = 'CN';

    /**
     * The default port for LDAP non-SSL connections
     */
    const ADLDAP_LDAP_PORT = '389';
    /**
     * The default port for LDAPS SSL connections
     */
    const ADLDAP_LDAPS_PORT = '636';

    /**
     * The account suffix for your domain, can be set when the class is invoked
     *
     * @var string
     */
    protected string $accountSuffix = "@mydomain.local";

    /**
     * The base dn for your domain
     *
     * If this is set to null then adLDAP will attempt to obtain this automatically from the rootDSE
     *
     * @var string
     */
    protected string $baseDn = "DC=mydomain,DC=local";

    /**
     * Port used to talk to the domain controllers.
     *
     * @var string|int
     */
    protected string|int $adPort = self::ADLDAP_LDAP_PORT;

    /**
     * Array of domain controllers. Specifiy multiple controllers if you
     * would like the class to balance the LDAP queries amongst multiple servers
     *
     * @var array
     */
    protected array $domainControllers = array("dc01.mydomain.local");

    /**
     * Optional account with higher privileges for searching
     * This should be set to a domain admin account
     *
     * @var string
     * @var string
     */
    protected ?string $adminUsername = NULL;
    protected ?string $adminPassword = NULL;

    /**
     * AD does not return the primary group. http://support.microsoft.com/?kbid=321360
     * This tweak will resolve the real primary group.
     * Setting to false will fudge "Domain Users" and is much faster. Keep in mind though that if
     * someone's primary group is NOT domain users, this is obviously going to mess up the results
     *
     * @var bool
     */
    protected bool $realPrimaryGroup = true;

    /**
     * Use SSL (LDAPS), your server needs to be setup, please see
     * http://adldap.sourceforge.net/wiki/doku.php?id=ldap_over_ssl
     *
     * @var bool
     */
    protected bool $useSSL = false;

    /**
     * Use TLS
     * If you wish to use TLS you should ensure that $useSSL is set to false and vice-versa
     *
     * @var bool
     */
    protected bool $useTLS = false;

    /**
     * Use SSO
     * To indicate to adLDAP to reuse password set by the brower through NTLM or Kerberos
     *
     * @var bool
     */
    protected bool $useSSO = false;

    /**
     * When querying group memberships, do it recursively
     * eg. User Fred is a member of Group A, which is a member of Group B, which is a member of Group C
     * user_ingroup("Fred","C") will returns true with this option turned on, false if turned off
     *
     * @var bool
     */
    protected bool $recursiveGroups = true;

    // You should not need to edit anything below this line
    //******************************************************************************************

    /**
     * Connection and bind default variables
     *
     * @var mixed
     * @var mixed
     */
    protected LDAP\Connection|bool $ldapConnection = false;
    protected bool $ldapBind = false;

    /**
     * Get the active LDAP Connection
     *
     * @return LDAP\Connection|bool
     */
    public function getLdapConnection(): LDAP\Connection|bool
    {
        if ($this->ldapConnection) {
            return $this->ldapConnection;
        }
        return false;
    }

    /**
     * Get the bind status
     *
     * @return bool
     */
    public function getLdapBind(): bool
    {
        return $this->ldapBind;
    }

    /**
     * Get the current base DN
     *
     * @return string
     */
    public function getBaseDn(): string
    {
        return $this->baseDn;
    }

    /**
     * The group class
     *
     * @var adLDAPGroups|null
     */
    protected ?adLDAPGroups $groupClass = null;

    /**
     * Get the group class interface
     *
     * @return adLDAPGroups
     */
    public function group(): adLDAPGroups
    {
        if (!$this->groupClass) {
            $this->groupClass = new adLDAPGroups($this);
        }
        return $this->groupClass;
    }

    /**
     * The user class
     *
     * @var adLDAPUsers|null
     */
    protected ?adLDAPUsers $userClass = null;

    /**
     * Get the userclass interface
     *
     * @return adLDAPUsers
     */
    public function user(): adLDAPUsers
    {
        if (!$this->userClass) {
            $this->userClass = new adLDAPUsers($this);
        }
        return $this->userClass;
    }

    /**
     * The folders class
     *
     * @var adLDAPFolders|null
     */
    protected ?adLDAPFolders $folderClass = null;

    /**
     * Get the folder class interface
     *
     * @return adLDAPFolders
     */
    public function folder(): adLDAPFolders
    {
        if (!$this->folderClass) {
            $this->folderClass = new adLDAPFolders($this);
        }
        return $this->folderClass;
    }

    /**
     * The utils class
     *
     * @var adLDAPUtils|null
     */
    protected ?adLDAPUtils $utilClass = null;

    /**
     * Get the utils class interface
     *
     * @return adLDAPUtils
     */
    public function utilities(): adLDAPUtils
    {
        if (!$this->utilClass) {
            $this->utilClass = new adLDAPUtils($this);
        }
        return $this->utilClass;
    }

    /**
     * The contacts class
     *
     * @var adLDAPContacts|null
     */
    protected ?adLDAPContacts $contactClass = null;

    /**
     * Get the contacts class interface
     *
     * @return adLDAPContacts
     */
    public function contact(): adLDAPContacts
    {
        if (!$this->contactClass) {
            $this->contactClass = new adLDAPContacts($this);
        }
        return $this->contactClass;
    }

    /**
     * The exchange class
     *
     * @var adLDAPExchange|null
     */
    protected ?adLDAPExchange $exchangeClass = null;

    /**
     * Get the exchange class interface
     *
     * @return adLDAPExchange
     */
    public function exchange(): adLDAPExchange
    {
        if (!$this->exchangeClass) {
            $this->exchangeClass = new adLDAPExchange($this);
        }
        return $this->exchangeClass;
    }

    /**
     * The computers class
     *
     * @var adLDAPComputers|null
     */
    // homola opravil
    //protected $computersClass;
    protected ?adLDAPComputers $computerClass = null;

    /**
     * Get the computers class interface
     *
     * @return adLDAPComputers
     */
    public function computer(): adLDAPComputers
    {
        if (!$this->computerClass) {
            $this->computerClass = new adLDAPComputers($this);
        }
        return $this->computerClass;
    }

    /**
     * Getters and Setters
     */

    /**
     * Set the account suffix
     *
     * @param string $accountSuffix
     * @return adLDAP
     */
    public function setAccountSuffix(string $accountSuffix): self
    {
        $this->accountSuffix = $accountSuffix;
        return $this;
    }

    /**
     * Get the account suffix
     *
     * @return string
     */
    public function getAccountSuffix(): string
    {
        return $this->accountSuffix;
    }

    /**
     * Set the domain controllers array
     *
     * @param array $domainControllers
     * @return adLDAP
     */
    public function setDomainControllers(array $domainControllers): self
    {
        $this->domainControllers = $domainControllers;
        return $this;
    }

    /**
     * Get the list of domain controllers
     *
     * @return array
     */
    public function getDomainControllers(): array
    {
        return $this->domainControllers;
    }

    /**
     * Sets the port number your domain controller communicates over
     *
     * @param string|int $adPort
     * @return adLDAP
     */
    public function setPort(string|int $adPort): self
    {
        $this->adPort = $adPort;
        return $this;
    }

    /**
     * Gets the port number your domain controller communicates over
     *
     * @return string|int
     */
    public function getPort(): string|int
    {
        return $this->adPort;
    }

    /**
     * Set the username of an account with higher priviledges
     *
     * @param string $adminUsername
     * @return adLDAP
     */
    public function setAdminUsername(string $adminUsername): self
    {
        $this->adminUsername = $adminUsername;
        return $this;
    }

    /**
     * Get the username of the account with higher priviledges
     *
     * This will throw an exception for security reasons
     */
    public function getAdminUsername(): string
    {
        throw new adLDAPException('For security reasons you cannot access the domain administrator account details');
    }

    /**
     * Set the password of an account with higher priviledges
     *
     * @param string $adminPassword
     * @return adLDAP
     */
    public function setAdminPassword(string $adminPassword): self
    {
        $this->adminPassword = $adminPassword;
        return $this;
    }

    /**
     * Get the password of the account with higher priviledges
     *
     * This will throw an exception for security reasons
     */
    public function getAdminPassword(): string
    {
        throw new adLDAPException('For security reasons you cannot access the domain administrator account details');
    }

    /**
     * Set whether to detect the true primary group
     *
     * @param bool $realPrimaryGroup
     * @return adLDAP
     */
    public function setRealPrimaryGroup(bool $realPrimaryGroup): self
    {
        $this->realPrimaryGroup = $realPrimaryGroup;
        return $this;
    }

    /**
     * Get the real primary group setting
     *
     * @return bool
     */
    public function getRealPrimaryGroup(): bool
    {
        return $this->realPrimaryGroup;
    }

    /**
     * Set whether to use SSL
     *
     * @param bool $useSSL
     * @return adLDAP
     */
    public function setUseSSL(bool $useSSL): self
    {
        $this->useSSL = $useSSL;
        // Set the default port correctly
        if ($this->useSSL) {
            $this->setPort(self::ADLDAP_LDAPS_PORT);
        } else {
            $this->setPort(self::ADLDAP_LDAP_PORT);
        }
        return $this;
    }

    /**
     * Get the SSL setting
     *
     * @return bool
     */
    public function getUseSSL(): bool
    {
        return $this->useSSL;
    }

    /**
     * Set whether to use TLS
     *
     * @param bool $useTLS
     * @return adLDAP
     */
    public function setUseTLS(bool $useTLS): self
    {
        $this->useTLS = $useTLS;
        return $this;
    }

    /**
     * Get the TLS setting
     *
     * @return bool
     */
    public function getUseTLS(): bool
    {
        return $this->useTLS;
    }

    /**
     * Set whether to use SSO
     * Requires ldap_sasl_bind support. Be sure --with-ldap-sasl is used when configuring PHP otherwise this function will be undefined.
     *
     * @param bool $useSSO
     * @return adLDAP
     * @throws adLDAPException
     */
    public function setUseSSO(bool $useSSO): self
    {
        if ($useSSO === true && !$this->ldapSaslSupported()) {
            throw new adLDAPException('No LDAP SASL support for PHP.  See: https://www.php.net/ldap_sasl_bind');
        }
        $this->useSSO = $useSSO;
        return $this;
    }

    /**
     * Get the SSO setting
     *
     * @return bool
     */
    public function getUseSSO(): bool
    {
        return $this->useSSO;
    }

    /**
     * Set whether to lookup recursive groups
     *
     * @param bool $recursiveGroups
     * @return adLDAP
     */
    public function setRecursiveGroups(bool $recursiveGroups): self
    {
        $this->recursiveGroups = $recursiveGroups;
        return $this;
    }

    /**
     * Get the recursive groups setting
     *
     * @return bool
     */
    public function getRecursiveGroups(): bool
    {
        return $this->recursiveGroups;
    }

    /**
     * Default Constructor
     *
     * Tries to bind to the AD domain over LDAP or LDAPs
     *
     * @param array $options Array of options to pass to the constructor
     * @throws adLDAPException if unable to bind to Domain Controller
     */
    function __construct(array $options = [])
    {
        // You can specifically overide any of the default configuration options setup above
        if (count($options) > 0) {
            if (array_key_exists("account_suffix", $options)) {
                $this->accountSuffix = $options["account_suffix"];
            }
            if (array_key_exists("base_dn", $options)) {
                $this->baseDn = $options["base_dn"];
            }
            if (array_key_exists("domain_controllers", $options)) {
                if (!is_array($options["domain_controllers"])) {
                    throw new adLDAPException('[domain_controllers] option must be an array');
                }
                $this->domainControllers = $options["domain_controllers"];
            }
            if (array_key_exists("admin_username", $options)) {
                $this->adminUsername = $options["admin_username"];
            }
            if (array_key_exists("admin_password", $options)) {
                $this->adminPassword = $options["admin_password"];
            }
            if (array_key_exists("real_primarygroup", $options)) {
                $this->realPrimaryGroup = $options["real_primarygroup"];
            }
            if (array_key_exists("use_ssl", $options)) {
                $this->setUseSSL($options["use_ssl"]);
            }
            if (array_key_exists("use_tls", $options)) {
                $this->useTLS = $options["use_tls"];
            }
            if (array_key_exists("recursive_groups", $options)) {
                $this->recursiveGroups = $options["recursive_groups"];
            }
            if (array_key_exists("ad_port", $options)) {
                $this->setPort($options["ad_port"]);
            }
            if (array_key_exists("sso", $options)) {
                $this->setUseSSO($options["sso"]);
                if (!$this->ldapSaslSupported()) {
                    $this->setUseSSO(false);
                }
            }
        }

        if ($this->ldapSupported() === false) {
            throw new adLDAPException('No LDAP support for PHP.  See: https://www.php.net/ldap');
        }

        return $this->connect();
    }

    /**
     * Default Destructor
     *
     * Closes the LDAP connection
     *
     * @return void
     */
    function __destruct()
    {
        $this->close();
    }

    /**
     * Connects and Binds to the Domain Controller
     *
     * @return bool
     * @throws adLDAPException
     */
    public function connect(): bool
    {
        // Connect to the AD/LDAP server as the username/password
        $domainController = $this->randomController();
        if ($this->useSSL) {
            // $this->ldapConnection = ldap_connect("ldaps://" . $domainController, $this->adPort);
            // PHP 8.3
            $this->ldapConnection = ldap_connect("ldaps://" . $domainController . ":" . $this->adPort);
        } else {
            // $this->ldapConnection = ldap_connect($domainController, $this->adPort);
            // PHP 8.3
            $this->ldapConnection = ldap_connect($domainController . ":" . $this->adPort);
        }

        // Set some ldap options for talking to AD
        ldap_set_option($this->ldapConnection, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($this->ldapConnection, LDAP_OPT_REFERRALS, 0);

        if ($this->useTLS) {
            ldap_start_tls($this->ldapConnection);
        }

        // Bind as a domain admin if they've set it up
        if ($this->adminUsername !== NULL && $this->adminPassword !== NULL) {
            $this->ldapBind = @ldap_bind($this->ldapConnection, $this->adminUsername . $this->accountSuffix, $this->adminPassword);
            if (!$this->ldapBind) {
                if ($this->useSSL && !$this->useTLS) {
                    // If you have problems troubleshooting, remove the @ character from the ldapldapBind command above to get the actual error message
                    throw new adLDAPException('Bind to Active Directory failed. Either the LDAPs connection failed or the login credentials are incorrect. AD said: ' . $this->getLastError());
                } else {
                    throw new adLDAPException('Bind to Active Directory failed. Check the login credentials and/or server details. AD said: ' . $this->getLastError());
                }
            }
        }
        if ($this->useSSO && $_SERVER['REMOTE_USER'] && $this->adminUsername === null && $_SERVER['KRB5CCNAME']) {
            putenv("KRB5CCNAME=" . $_SERVER['KRB5CCNAME']);
            $this->ldapBind = @ldap_sasl_bind($this->ldapConnection, NULL, NULL, "GSSAPI");
            if (!$this->ldapBind) {
                throw new adLDAPException('Rebind to Active Directory failed. AD said: ' . $this->getLastError());
            } else {
                return true;
            }
        }


        if ($this->baseDn == NULL) {
            $this->baseDn = $this->findBaseDn();
        }

        return true;
    }

    /**
     * Closes the LDAP connection
     *
     * @return void
     */
    public function close(): void
    {
        if ($this->ldapConnection) {
            @ldap_close($this->ldapConnection);
        }
    }

    /**
     * Validate a user's login credentials
     *
     * @param string|null $username A user's AD username
     * @param string|null $password A user's AD password
     * @param bool $preventRebind
     * @return bool
     * @throws adLDAPException
     */
    public function authenticate(?string $username,?string $password,bool $preventRebind = false): bool
    {
        // Prevent null binding
        if ($username === NULL || $password === NULL) {
            return false;
        }
        if (empty($username) || empty($password)) {
            return false;
        }

        // Allow binding over SSO for Kerberos
        if ($this->useSSO && $_SERVER['REMOTE_USER'] && $_SERVER['REMOTE_USER'] == $username && $this->adminUsername === NULL && $_SERVER['KRB5CCNAME']) {
            putenv("KRB5CCNAME=" . $_SERVER['KRB5CCNAME']);
            $this->ldapBind = @ldap_sasl_bind($this->ldapConnection, NULL, NULL, "GSSAPI");
            if (!$this->ldapBind) {
                throw new adLDAPException('Rebind to Active Directory failed. AD said: ' . $this->getLastError());
            } else {
                return true;
            }
        }

        // Bind as the user
        $ret = true;
        $this->ldapBind = @ldap_bind($this->ldapConnection, $username . $this->accountSuffix, $password);
        if (!$this->ldapBind) {
            $ret = false;
        }

        // Cnce we've checked their details, kick back into admin mode if we have it
        if ($this->adminUsername !== NULL && !$preventRebind) {
            $this->ldapBind = @ldap_bind($this->ldapConnection, $this->adminUsername . $this->accountSuffix, $this->adminPassword);
            if (!$this->ldapBind) {
                // This should never happen in theory
                throw new adLDAPException('Rebind to Active Directory failed. AD said: ' . $this->getLastError());
            }
        }

        return $ret;
    }

    /**
     * Find the Base DN of your domain controller
     *
     * @return string
     */
    public function findBaseDn(): string
    {
        $namingContext = $this->getRootDse(array('defaultnamingcontext'));
        return $namingContext[0]['defaultnamingcontext'][0];
    }

    /**
     * Get the RootDSE properties from a domain controller
     *
     * @param array $attributes The attributes you wish to query e.g. defaultnamingcontext
     * @return array
     */
    public function getRootDse(array $attributes = ["*", "+"]): array
    {
        if (!$this->ldapBind) {
            return [];
        }

        $sr = @ldap_read($this->ldapConnection, NULL, 'objectClass=*', $attributes);
        $entries = @ldap_get_entries($this->ldapConnection, $sr);
        return $entries;
    }

    /**
     * Get last error from Active Directory
     *
     * This function gets the last message from Active Directory
     * This may indeed be a 'Success' message but if you get an unknown error
     * it might be worth calling this function to see what errors were raised
     *
     * return string
     */
    public function getLastError(): string
    {
        return @ldap_error($this->ldapConnection);
    }

    /**
     * Detect LDAP support in php
     *
     * @return bool
     */
    protected function ldapSupported(): bool
    {
        if (!function_exists('ldap_connect')) {
            return false;
        }
        return true;
    }

    /**
     * Detect ldap_sasl_bind support in PHP
     *
     * @return bool
     */
    protected function ldapSaslSupported(): bool
    {
        if (!function_exists('ldap_sasl_bind')) {
            return false;
        }
        return true;
    }

    /**
     * Schema
     *
     * @param array $attributes Attributes to be queried
     * @return array
     */
    public function adldap_schema(array $attributes): array
    {

        // LDAP doesn't like NULL attributes, only set them if they have values
        // If you wish to remove an attribute you should set it to a space
        // TO DO: Adapt user_modify to use ldap_mod_delete to remove a NULL attribute
        $mod = [];

        // Check every attribute to see if it contains 8bit characters and then UTF8 encode them
        array_walk($attributes, array($this, 'encode8bit'));

        // Homola odstranil notice Undefined index:

        if (isset($attributes["address_city"])) {
            $mod["l"][0] = $attributes["address_city"];
        }
        if (isset($attributes["address_code"])) {
            $mod["postalCode"][0] = $attributes["address_code"];
        }
        //if ($attributes["address_country"]){ $mod["countryCode"][0]=$attributes["address_country"]; } // use country codes?
        if (isset($attributes["address_country"])) {
            $mod["c"][0] = $attributes["address_country"];
        }
        if (isset($attributes["address_pobox"])) {
            $mod["postOfficeBox"][0] = $attributes["address_pobox"];
        }
        if (isset($attributes["address_state"])) {
            $mod["st"][0] = $attributes["address_state"];
        }
        if (isset($attributes["address_street"])) {
            $mod["streetAddress"][0] = $attributes["address_street"];
        }
        if (isset($attributes["company"])) {
            $mod["company"][0] = $attributes["company"];
        }
        if (isset($attributes["change_password"])) {
            $mod["pwdLastSet"][0] = 0;
        }
        if (isset($attributes["department"])) {
            $mod["department"][0] = $attributes["department"];
        }
        if (isset($attributes["description"])) {
            $mod["description"][0] = $attributes["description"];
        }
        if (isset($attributes["display_name"])) {
            $mod["displayName"][0] = $attributes["display_name"];
        }
        if (isset($attributes["email"])) {
            $mod["mail"][0] = $attributes["email"];
        }
        if (isset($attributes["expires"])) {
            $mod["accountExpires"][0] = $attributes["expires"];
        } //unix epoch format?
        if (isset($attributes["firstname"])) {
            $mod["givenName"][0] = $attributes["firstname"];
        }
        if (isset($attributes["home_directory"])) {
            $mod["homeDirectory"][0] = $attributes["home_directory"];
        }
        if (isset($attributes["home_drive"])) {
            $mod["homeDrive"][0] = $attributes["home_drive"];
        }
        if (isset($attributes["initials"])) {
            $mod["initials"][0] = $attributes["initials"];
        }
        if (isset($attributes["logon_name"])) {
            $mod["userPrincipalName"][0] = $attributes["logon_name"];
        }
        if (isset($attributes["manager"])) {
            $mod["manager"][0] = $attributes["manager"];
        }  //UNTESTED ***Use DistinguishedName***
        if (isset($attributes["office"])) {
            $mod["physicalDeliveryOfficeName"][0] = $attributes["office"];
        }
        if (isset($attributes["password"])) {
            $mod["unicodePwd"][0] = $this->user()->encodePassword($attributes["password"]);
        }
        if (isset($attributes["profile_path"])) {
            $mod["profilepath"][0] = $attributes["profile_path"];
        }
        if (isset($attributes["script_path"])) {
            $mod["scriptPath"][0] = $attributes["script_path"];
        }
        if (isset($attributes["surname"])) {
            $mod["sn"][0] = $attributes["surname"];
        }
        if (isset($attributes["title"])) {
            $mod["title"][0] = $attributes["title"];
        }
        if (isset($attributes["telephone"])) {
            $mod["telephoneNumber"][0] = $attributes["telephone"];
        }
        if (isset($attributes["mobile"])) {
            $mod["mobile"][0] = $attributes["mobile"];
        }
        if (isset($attributes["pager"])) {
            $mod["pager"][0] = $attributes["pager"];
        }
        if (isset($attributes["ipphone"])) {
            $mod["ipphone"][0] = $attributes["ipphone"];
        }
        if (isset($attributes["web_page"])) {
            $mod["wWWHomePage"][0] = $attributes["web_page"];
        }
        if (isset($attributes["fax"])) {
            $mod["facsimileTelephoneNumber"][0] = $attributes["fax"];
        }
        if (isset($attributes["enabled"])) {
            $mod["userAccountControl"][0] = $attributes["enabled"];
        }
        if (isset($attributes["homephone"])) {
            $mod["homephone"][0] = $attributes["homephone"];
        }

        // Distribution List specific schema
        if (isset($attributes["group_sendpermission"])) {
            $mod["dlMemSubmitPerms"][0] = $attributes["group_sendpermission"];
        }
        if (isset($attributes["group_rejectpermission"])) {
            $mod["dlMemRejectPerms"][0] = $attributes["group_rejectpermission"];
        }

        // Exchange Schema
        if (isset($attributes["exchange_homemdb"])) {
            $mod["homeMDB"][0] = $attributes["exchange_homemdb"];
        }
        if (isset($attributes["exchange_mailnickname"])) {
            $mod["mailNickname"][0] = $attributes["exchange_mailnickname"];
        }
        if (isset($attributes["exchange_proxyaddress"])) {
            $mod["proxyAddresses"][0] = $attributes["exchange_proxyaddress"];
        }
        if (isset($attributes["exchange_usedefaults"])) {
            $mod["mDBUseDefaults"][0] = $attributes["exchange_usedefaults"];
        }
        if (isset($attributes["exchange_policyexclude"])) {
            $mod["msExchPoliciesExcluded"][0] = $attributes["exchange_policyexclude"];
        }
        if (isset($attributes["exchange_policyinclude"])) {
            $mod["msExchPoliciesIncluded"][0] = $attributes["exchange_policyinclude"];
        }
        if (isset($attributes["exchange_addressbook"])) {
            $mod["showInAddressBook"][0] = $attributes["exchange_addressbook"];
        }
        if (isset($attributes["exchange_altrecipient"])) {
            $mod["altRecipient"][0] = $attributes["exchange_altrecipient"];
        }
        if (isset($attributes["exchange_deliverandredirect"])) {
            $mod["deliverAndRedirect"][0] = $attributes["exchange_deliverandredirect"];
        }
        // This schema is designed for contacts
        if (isset($attributes["exchange_hidefromlists"])) {
            $mod["msExchHideFromAddressLists"][0] = $attributes["exchange_hidefromlists"];
        }
        if (isset($attributes["contact_email"])) {
            $mod["targetAddress"][0] = $attributes["contact_email"];
        }


        //echo ("<pre>"); print_r($mod);
        /*
        // modifying a name is a bit fiddly
        if ($attributes["firstname"] && $attributes["surname"]){
            $mod["cn"][0]=$attributes["firstname"]." ".$attributes["surname"];
            $mod["displayname"][0]=$attributes["firstname"]." ".$attributes["surname"];
            $mod["name"][0]=$attributes["firstname"]." ".$attributes["surname"];
        }
        */

        /*if (count($mod) == 0) {
            return false;
            return [];
        }*/
        return ($mod);
    }

    /**
     * Convert 8bit characters e.g. accented characters to UTF8 encoded characters
     */
    protected function encode8Bit(mixed &$item,string|int $key): void
    {
        $encode = false;
        if (is_string($item)) {
            for ($i = 0; $i < strlen($item); $i++) {
                if (ord($item[$i]) >> 7) {
                    $encode = true;
                }
            }
        }
        if ($encode === true && $key != 'password') {
            // utf8_encode has been DEPRECATED as of PHP 8.2.0.
            //$item = utf8_encode($item);
            $item = mb_convert_encoding($item, 'UTF-8', 'ISO-8859-1');
        }
    }

    /**
    * Select a random domain controller from your domain controller array
    * 
    * @return string
    */
    protected function randomController(): string
    {
        // PHP 8.1
        // ErrorException
        //Deprecated: Implicit conversion from float 60458500.00000001 to int loses precision
        #mt_srand(doubleval(microtime()) * 100000000); // For older PHP versions
        mt_srand(intval(doubleval(microtime()) * 100000000)); // For older PHP versions
        /*if (sizeof($this->domainControllers) > 1) {
            $adController = $this->domainControllers[array_rand($this->domainControllers)]; 
            // Test if the controller is responding to pings
            $ping = $this->pingController($adController); 
            if ($ping === false) { 
                // Find the current key in the domain controllers array
                $key = array_search($adController, $this->domainControllers);
                // Remove it so that we don't end up in a recursive loop
                unset($this->domainControllers[$key]);
                // Select a new controller
                return $this->randomController(); 
            }
            else { 
                return ($adController); 
            }
        } */
        return $this->domainControllers[array_rand($this->domainControllers)];
    }

    /**
     * Test basic connectivity to controller
     *
     * @param string $host
     * @return bool
     */
    protected function pingController(string $host):bool
    {
        $port = $this->adPort;
        fsockopen($host, $port, $errno, $errstr, 10);
        if ($errno > 0) {
            return false;
        }
        return true;
    }
}

