<?php

namespace adLDAP;
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
 * @subpackage Exchange
 * @author Scott Barnett, Richard Hyland
 * @copyright (c) 2006-2012 Scott Barnett, Richard Hyland
 * @license http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html LGPLv2.1
 * @revision $Revision: 97 $
 * @version 4.0.4
 * @link http://adldap.sourceforge.net/
 */
require_once(dirname(__FILE__) . '/../adLDAP.php');

/**
 * MICROSOFT EXCHANGE FUNCTIONS
 */
class adLDAPExchange
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
     * Create an Exchange account
     *
     * @param null|string $username The username of the user to add the Exchange account to
     * @param null|array $storageGroup The mailbox, Exchange Storage Group, for the user account, this must be a full CN
     *                            If the storage group has a different base_dn to the adLDAP configuration, set it using $base_dn
     * @param null|string $emailAddress The primary email address to add to this user
     * @param null|string $mailNickname The mail nick name.  If mail nickname is blank, the username will be used
     * @param bool $useDefaults Indicates whether the store should use the default quota, rather than the per-mailbox quota.
     * @param null|string $baseDn Specify an alternative base_dn for the Exchange storage group
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return bool
     * @throws adLDAPException
     */
    public function createMailbox(?string $username,?array $storageGroup,?string $emailAddress,?string $mailNickname = NULL,bool $useDefaults = TRUE,?string $baseDn = NULL,bool $isGUID = false): bool
    {
        if ($username === NULL) {
            throw new adLDAPException("Missing compulsory field [username]");
        }
        if ($storageGroup === NULL) {
            throw new adLDAPException( "Missing compulsory array [storagegroup]");
        }
        if (!is_array($storageGroup)) {
            throw new adLDAPException( "[storagegroup] must be an array");
        }
        if ($emailAddress === NULL) {
            throw new adLDAPException( "Missing compulsory field [emailAddress]");
        }

        if ($baseDn === NULL) {
            $baseDn = $this->adldap->getBaseDn();
        }

        $container = "CN=" . implode(",CN=", $storageGroup);

        if ($mailNickname === NULL) {
            $mailNickname = $username;
        }
        $mdbUseDefaults = $this->adldap->utilities()->boolToStr($useDefaults);

        $attributes = array(
            'exchange_homemdb' => $container . "," . $baseDn,
            'exchange_proxyaddress' => 'SMTP:' . $emailAddress,
            'exchange_mailnickname' => $mailNickname,
            'exchange_usedefaults' => $mdbUseDefaults
        );
        $result = $this->adldap->user()->modify($username, $attributes, $isGUID);
        if (!$result) {
            return false;
        }
        return true;
    }

    /**
     * Add an X400 address to Exchange
     * See http://tools.ietf.org/html/rfc1685 for more information.
     * An X400 Address looks similar to this X400:c=US;a= ;p=Domain;o=Organization;s=Doe;g=John;
     *
     * @param null|string $username The username of the user to add the X400 to to
     * @param string $country Country
     * @param string $admd Administration Management Domain
     * @param string $pdmd Private Management Domain (often your AD domain)
     * @param string $org Organization
     * @param string $surname Surname
     * @param string $givenName Given name
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return bool
     * @throws adLDAPException
     */
    public function addX400(?string $username,string $country,string $admd,string $pdmd,string $org,string $surname,string $givenName,bool $isGUID = false): bool
    {
        if ($username === NULL) {
            throw new adLDAPException("Missing compulsory field [username]");
        }

        $proxyValue = 'X400:';

        // Find the dn of the user
        $user = $this->adldap->user()->info($username, array("cn", "proxyaddresses"), $isGUID);
        if (!$user) return false;
        if ($user[0]["dn"] === NULL) {
            return false;
        }
        $userDn = $user[0]["dn"];

        // We do not have to demote an email address from the default so we can just add the new proxy address
        $attributes['exchange_proxyaddress'] = $proxyValue . 'c=' . $country . ';a=' . $admd . ';p=' . $pdmd . ';o=' . $org . ';s=' . $surname . ';g=' . $givenName . ';';

        // Translate the update to the LDAP schema                
        $add = $this->adldap->adldap_schema($attributes);

        if (!$add) {
            return false;
        }

        // Do the update
        // Take out the @ to see any errors, usually this error might occur because the address already
        // exists in the list of proxyAddresses
        $result = @ldap_mod_add($this->adldap->getLdapConnection(), $userDn, $add);
        if (!$result) {
            return false;
        }

        return true;
    }

    /**
     * Add an address to Exchange
     *
     * @param null|string $username The username of the user to add the Exchange account to
     * @param null|string $emailAddress The email address to add to this user
     * @param bool $default Make this email address the default address, this is a bit more intensive as we have to demote any existing default addresses
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return bool
     * @throws adLDAPException
     */
    public function addAddress(?string $username,?string $emailAddress,bool $default = FALSE,bool $isGUID = false): bool
    {
        if ($username === NULL) {
            throw new adLDAPException("Missing compulsory field [username]");
        }
        if ($emailAddress === NULL) {
            throw new adLDAPException("Missing compulsory fields [emailAddress]");
        }

        $proxyValue = 'smtp:';
        if ($default === true) {
            $proxyValue = 'SMTP:';
        }

        // Find the dn of the user
        $user = $this->adldap->user()->info($username, array("cn", "proxyaddresses"), $isGUID);
        if (!$user) return false;
        if ($user[0]["dn"] === NULL) {
            return false;
        }
        $userDn = $user[0]["dn"];

        // We need to scan existing proxy addresses and demote the default one
        if (is_array($user[0]["proxyaddresses"]) && $default === true) {
            $modAddresses = [];
            for ($i = 0; $i < sizeof($user[0]['proxyaddresses']); $i++) {
                if (str_contains($user[0]['proxyaddresses'][$i], 'SMTP:')) {
                    $user[0]['proxyaddresses'][$i] = str_replace('SMTP:', 'smtp:', $user[0]['proxyaddresses'][$i]);
                }
                if ($user[0]['proxyaddresses'][$i] != '') {
                    $modAddresses['proxyAddresses'][$i] = $user[0]['proxyaddresses'][$i];
                }
            }
            $modAddresses['proxyAddresses'][(sizeof($user[0]['proxyaddresses']) - 1)] = 'SMTP:' . $emailAddress;

            $result = @ldap_mod_replace($this->adldap->getLdapConnection(), $userDn, $modAddresses);
            if (!$result) {
                return false;
            }

            return true;
        } else {
            // We do not have to demote an email address from the default so we can just add the new proxy address
            $attributes['exchange_proxyaddress'] = $proxyValue . $emailAddress;

            // Translate the update to the LDAP schema                
            $add = $this->adldap->adldap_schema($attributes);

            if (!$add) {
                return false;
            }

            // Do the update
            // Take out the @ to see any errors, usually this error might occur because the address already
            // exists in the list of proxyAddresses
            $result = @ldap_mod_add($this->adldap->getLdapConnection(), $userDn, $add);
            if (!$result) {
                return false;
            }

            return true;
        }
    }

    /**
     * Remove an address to Exchange
     * If you remove a default address the account will no longer have a default,
     * we recommend changing the default address first
     *
     * @param null|string $username The username of the user to add the Exchange account to
     * @param null|string $emailAddress The email address to add to this user
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return bool
     * @throws adLDAPException
     */
    public function deleteAddress(?string $username,?string $emailAddress,bool $isGUID = false): bool
    {
        if ($username === NULL) {
            throw new adLDAPException("Missing compulsory field [username]");
        }
        if ($emailAddress === NULL) {
            throw new adLDAPException( "Missing compulsory fields [emailAddress]");
        }

        // Find the dn of the user
        $user = $this->adldap->user()->info($username, array("cn", "proxyaddresses"), $isGUID);
        if (!$user) return false;
        if ($user[0]["dn"] === NULL) {
            return false;
        }
        $userDn = $user[0]["dn"];

        if (is_array($user[0]["proxyaddresses"])) {
            $mod = array();
            for ($i = 0; $i < sizeof($user[0]['proxyaddresses']); $i++) {
                if (str_contains($user[0]['proxyaddresses'][$i], 'SMTP:') && $user[0]['proxyaddresses'][$i] == 'SMTP:' . $emailAddress) {
                    $mod['proxyAddresses'][0] = 'SMTP:' . $emailAddress;
                } elseif (str_contains($user[0]['proxyaddresses'][$i], 'smtp:') && $user[0]['proxyaddresses'][$i] == 'smtp:' . $emailAddress) {
                    $mod['proxyAddresses'][0] = 'smtp:' . $emailAddress;
                }
            }

            $result = @ldap_mod_del($this->adldap->getLdapConnection(), $userDn, $mod);
            if (!$result) {
                return false;
            }

            return true;
        } else {
            return false;
        }
    }

    /**
     * Change the default address
     *
     * @param null|string $username The username of the user to add the Exchange account to
     * @param null|string $emailAddress The email address to make default
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return bool
     * @throws adLDAPException
     */
    public function primaryAddress(?string $username,?string $emailAddress,bool $isGUID = false):bool
    {
        if ($username === NULL) {
            throw new adLDAPException( "Missing compulsory field [username]");
        }
        if ($emailAddress === NULL) {
            throw new adLDAPException("Missing compulsory fields [emailAddress]");
        }

        // Find the dn of the user
        $user = $this->adldap->user()->info($username, array("cn", "proxyaddresses"), $isGUID);
        if (!$user) return false;
        if ($user[0]["dn"] === NULL) {
            return false;
        }
        $userDn = $user[0]["dn"];

        if (is_array($user[0]["proxyaddresses"])) {
            $modAddresses = array();
            for ($i = 0; $i < sizeof($user[0]['proxyaddresses']); $i++) {
                if (str_contains($user[0]['proxyaddresses'][$i], 'SMTP:')) {
                    $user[0]['proxyaddresses'][$i] = str_replace('SMTP:', 'smtp:', $user[0]['proxyaddresses'][$i]);
                }
                if ($user[0]['proxyaddresses'][$i] == 'smtp:' . $emailAddress) {
                    $user[0]['proxyaddresses'][$i] = str_replace('smtp:', 'SMTP:', $user[0]['proxyaddresses'][$i]);
                }
                if ($user[0]['proxyaddresses'][$i] != '') {
                    $modAddresses['proxyAddresses'][$i] = $user[0]['proxyaddresses'][$i];
                }
            }

            $result = @ldap_mod_replace($this->adldap->getLdapConnection(), $userDn, $modAddresses);
            if (!$result) {
                return false;
            }

            return true;
        }
        return false;

    }

    /**
     * Mail enable a contact
     * Allows email to be sent to them through Exchange
     *
     * @param null|string $distinguishedName The contact to mail enable
     * @param null|string $emailAddress The email address to allow emails to be sent through
     * @param null|string $mailNickname The mailnickname for the contact in Exchange.  If NULL this will be set to the display name
     * @return bool
     * @throws adLDAPException
     */
    public function contactMailEnable(?string $distinguishedName,?string $emailAddress,?string $mailNickname = NULL): bool
    {
        if ($distinguishedName === NULL) {
            throw new adLDAPException("Missing compulsory field [distinguishedName]");
        }
        if ($emailAddress === NULL) {
            throw new adLDAPException("Missing compulsory field [emailAddress]");
        }

        if ($mailNickname !== NULL) {
            // Find the dn of the user
            $user = $this->adldap->contact()->info($distinguishedName, array("cn", "displayname"));
            if (!$user) return false;
            if ($user[0]["displayname"] === NULL) {
                return false;
            }
            $mailNickname = $user[0]['displayname'][0];
        }

        $attributes = array("email" => $emailAddress, "contact_email" => "SMTP:" . $emailAddress, "exchange_proxyaddress" => "SMTP:" . $emailAddress, "exchange_mailnickname" => $mailNickname);

        // Translate the update to the LDAP schema                
        $mod = $this->adldap->adldap_schema($attributes);

        // Check to see if this is an enabled status update
        if (!$mod) {
            return false;
        }

        // Do the update
        $result = ldap_modify($this->adldap->getLdapConnection(), $distinguishedName, $mod);
        if (!$result) {
            return false;
        }

        return true;
    }

    /**
     * Returns a list of Exchange Servers in the ConfigurationNamingContext of the domain
     *
     * @param array $attributes An array of the AD attributes you wish to return
     * @return array|false
     */
    public function servers(array $attributes = ['cn', 'distinguishedname', 'serialnumber']): array|false
    {
        if (!$this->adldap->getLdapBind()) {
            return false;
        }

        $configurationNamingContext = $this->adldap->getRootDse(array('configurationnamingcontext'));
        if ($sr = @ldap_search($this->adldap->getLdapConnection(), $configurationNamingContext[0]['configurationnamingcontext'][0], '(&(objectCategory=msExchExchangeServer))', $attributes)) {
            $entries = @ldap_get_entries($this->adldap->getLdapConnection(), $sr);
            return $entries;
        } else {
            return false;
        }
    }

    /**
     * Returns a list of Storage Groups in Exchange for a given mail server
     *
     * @param null|string $exchangeServer The full DN of an Exchange server.  You can use exchange_servers() to find the DN for your server
     * @param array $attributes An array of the AD attributes you wish to return
     * @param bool $recursive If enabled this will automatically query the databases within a storage group
     * @return array|false
     * @throws adLDAPException
     */
    public function storageGroups(?string $exchangeServer,array $attributes = ['cn', 'distinguishedname'],bool $recursive = NULL): array|false
    {
        if (!$this->adldap->getLdapBind()) {
            return false;
        }
        if ($exchangeServer === NULL) {
            throw new adLDAPException("Missing compulsory field [exchangeServer]");
        }
        if ($recursive === NULL) {
            $recursive = $this->adldap->getRecursiveGroups();
        }

        $filter = '(&(objectCategory=msExchStorageGroup))';
        if ($sr = @ldap_search($this->adldap->getLdapConnection(), $exchangeServer, $filter, $attributes)) {
            $entries = @ldap_get_entries($this->adldap->getLdapConnection(), $sr);

            if (($entries) and ($recursive === true)) {
                for ($i = 0; $i < $entries['count']; $i++) {
                    $entries[$i]['msexchprivatemdb'] = $this->storageDatabases($entries[$i]['distinguishedname'][0]);
                }
            }

            return $entries;
        } else {
            return false;
        }

    }

    /**
     * Returns a list of Databases within any given storage group in Exchange for a given mail server
     *
     * @param null|string $storageGroup The full DN of an Storage Group.  You can use exchange_storage_groups() to find the DN
     * @param array $attributes An array of the AD attributes you wish to return
     * @return array|false
     * @throws adLDAPException
     */
    public function storageDatabases(?string $storageGroup,array $attributes = ['cn', 'distinguishedname', 'displayname']): array|false
    {
        if (!$this->adldap->getLdapBind()) {
            return false;
        }
        if ($storageGroup === NULL) {
            throw new adLDAPException("Missing compulsory field [storageGroup]");
        }

        $filter = '(&(objectCategory=msExchPrivateMDB))';
        if ($sr = @ldap_search($this->adldap->getLdapConnection(), $storageGroup, $filter, $attributes)) {
            $entries = @ldap_get_entries($this->adldap->getLdapConnection(), $sr);
            return $entries;
        } else {
            return false;
        }
    }
}
