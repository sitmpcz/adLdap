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
 * @subpackage Groups
 * @author Scott Barnett, Richard Hyland
 * @copyright (c) 2006-2012 Scott Barnett, Richard Hyland
 * @license http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html LGPLv2.1
 * @revision $Revision: 97 $
 * @version 4.0.4
 * @link http://adldap.sourceforge.net/
 */
require_once(dirname(__FILE__) . '/../adLDAP.php');
require_once(dirname(__FILE__) . '/../collections/adLDAPGroupCollection.php');

/**
 * GROUP FUNCTIONS
 */
class adLDAPGroups
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
     * Add a group to a group
     *
     * @param string $parent The parent group name
     * @param string $child The child group name
     * @return bool
     */
    public function addGroup(string $parent,string $child): bool
    {

        // Find the parent group's dn
        $parentGroup = $this->info($parent, array("cn"));
        if ($parentGroup[0]["dn"] === NULL) {
            return false;
        }
        $parentDn = $parentGroup[0]["dn"];

        // Find the child group's dn
        $childGroup = $this->info($child, array("cn"));
        if ($childGroup[0]["dn"] === NULL) {
            return false;
        }
        $childDn = $childGroup[0]["dn"];

        $add = array();
        $add["member"] = $childDn;

        $result = @ldap_mod_add($this->adldap->getLdapConnection(), $parentDn, $add);
        if (!$result) {
            return false;
        }
        return true;
    }

    /**
     * Add a user to a group
     *
     * @param string $group The group to add the user to
     * @param string $user The user to add to the group
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return bool
     */
    public function addUser(string $group,string $user,bool $isGUID = false): bool
    {
        // Adding a user is a bit fiddly, we need to get the full DN of the user
        // and add it using the full DN of the group

        // Find the user's dn
        $userDn = $this->adldap->user()->dn($user, $isGUID);
        if ($userDn === false) {
            return false;
        }

        // Find the group's dn
        $groupInfo = $this->info($group, array("cn"));
        if ((!$groupInfo) or ($groupInfo[0]["dn"] === NULL)) {
            return false;
        }
        $groupDn = $groupInfo[0]["dn"];

        $add = array();
        $add["member"] = $userDn;

        $result = @ldap_mod_add($this->adldap->getLdapConnection(), $groupDn, $add);
        if (!$result) {
            return false;
        }
        return true;
    }

    /**
     * Add a contact to a group
     *
     * @param string $group The group to add the contact to
     * @param string $contactDn The DN of the contact to add
     * @return bool
     */
    public function addContact(string $group,string  $contactDn): bool
    {
        // To add a contact we take the contact's DN
        // and add it using the full DN of the group

        // Find the group's dn
        $groupInfo = $this->info($group, array("cn"));
        if ($groupInfo[0]["dn"] === NULL) {
            return false;
        }
        $groupDn = $groupInfo[0]["dn"];

        $add = array();
        $add["member"] = $contactDn;

        $result = @ldap_mod_add($this->adldap->getLdapConnection(), $groupDn, $add);
        if (!$result) {
            return false;
        }
        return true;
    }

    /**
     * Create a group
     *
     * @param array $attributes Default attributes of the group
     * @return bool
     * @throws adLDAPException
     */
    public function create(array $attributes): bool
    {
        if (!is_array($attributes)) {
            throw new adLDAPException( "Attributes must be an array");
        }
        if (!array_key_exists("group_name", $attributes)) {
            throw new adLDAPException( "Missing compulsory field [group_name]");
        }
        if (!array_key_exists("container", $attributes)) {
            throw new adLDAPException( "Missing compulsory field [container]");
        }
        if (!array_key_exists("description", $attributes)) {
            throw new adLDAPException( "Missing compulsory field [description]");
        }
        if (!is_array($attributes["container"])) {
            throw new adLDAPException( "Container attribute must be an array.");
        }
        $attributes["container"] = array_reverse($attributes["container"]);

        //$member_array = array();
        //$member_array[0] = "cn=user1,cn=Users,dc=yourdomain,dc=com";
        //$member_array[1] = "cn=administrator,cn=Users,dc=yourdomain,dc=com";

        $add = array();
        $add["cn"] = $attributes["group_name"];
        $add["samaccountname"] = $attributes["group_name"];
        $add["objectClass"] = "Group";
        $add["description"] = $attributes["description"];
        //$add["member"] = $member_array; UNTESTED

        $container = "OU=" . implode(",OU=", $attributes["container"]);
        $result = ldap_add($this->adldap->getLdapConnection(), "CN=" . $add["cn"] . ", " . $container . "," . $this->adldap->getBaseDn(), $add);
        if (!$result) {
            return false;
        }
        return true;
    }

    /**
     * Delete a group account
     *
     * @param null|string $group The group to delete (please be careful here!)
     *
     * @return bool
     * @throws adLDAPException
     */
    public function delete(?string $group): bool
    {
        if (!$this->adldap->getLdapBind()) {
            return false;
        }
        if ($group === null) {
            throw new adLDAPException( "Missing compulsory field [group]");
        }

        $groupInfo = $this->info($group, array("*"));
        $dn = $groupInfo[0]['distinguishedname'][0];
        $result = $this->adldap->folder()->delete($dn);
        if ($result !== true) {
            return false;
        }
        return true;
    }

    /**
     * Remove a group from a group
     *
     * @param string $parent The parent group name
     * @param string $child The child group name
     * @return bool
     */
    public function removeGroup(string $parent,string $child): bool
    {

        // Find the parent dn
        $parentGroup = $this->info($parent, array("cn"));
        if ($parentGroup[0]["dn"] === NULL) {
            return false;
        }
        $parentDn = $parentGroup[0]["dn"];

        // Find the child dn
        $childGroup = $this->info($child, array("cn"));
        if ($childGroup[0]["dn"] === NULL) {
            return false;
        }
        $childDn = $childGroup[0]["dn"];

        $del = array();
        $del["member"] = $childDn;

        $result = @ldap_mod_del($this->adldap->getLdapConnection(), $parentDn, $del);
        if (!$result) {
            return false;
        }
        return true;
    }

    /**
     * Remove a user from a group
     *
     * @param string $group The group to remove a user from
     * @param string $user The AD user to remove from the group
     * @param bool $isGUID Is the username passed a GUID or a samAccountName
     * @return bool
     */
    public function removeUser(string $group,string $user,bool $isGUID = false): bool
    {

        // Find the parent dn
        $groupInfo = $this->info($group, array("cn"));
        if ($groupInfo[0]["dn"] === NULL) {
            return false;
        }
        $groupDn = $groupInfo[0]["dn"];

        // Find the users dn
        $userDn = $this->adldap->user()->dn($user, $isGUID);
        if ($userDn === false) {
            return false;
        }

        $del = array();
        $del["member"] = $userDn;

        $result = @ldap_mod_del($this->adldap->getLdapConnection(), $groupDn, $del);
        if (!$result) {
            return false;
        }
        return true;
    }

    /**
     * Remove a contact from a group
     *
     * @param string $group The group to remove a user from
     * @param string $contactDn The DN of a contact to remove from the group
     * @return bool
     */
    public function removeContact(string $group,string $contactDn): bool
    {

        // Find the parent dn
        $groupInfo = $this->info($group, array("cn"));
        if ($groupInfo[0]["dn"] === NULL) {
            return false;
        }
        $groupDn = $groupInfo[0]["dn"];

        $del = array();
        $del["member"] = $contactDn;

        $result = @ldap_mod_del($this->adldap->getLdapConnection(), $groupDn, $del);
        if (!$result) {
            return false;
        }
        return true;
    }

    /**
     * Return a list of groups in a group
     *
     * @param string $group The group to query
     * @param bool $recursive Recursively get groups
     * @return array|false
     */
    public function inGroup(string $group,?bool $recursive = NULL): array|false
    {
        if (!$this->adldap->getLdapBind()) {
            return false;
        }
        if ($recursive === NULL) {
            $recursive = $this->adldap->getRecursiveGroups();
        } // Use the default option if they haven't set it

        // Search the directory for the members of a group
        $info = $this->info($group, array("member", "cn"));
        $groups = $info[0]["member"];
        if (!is_array($groups)) {
            return false;
        }

        $groupArray = [];

        for ($i = 0; $i < $groups["count"]; $i++) {
            $filter = "(&(objectCategory=group)(distinguishedName=" . $this->adldap->utilities()->ldapSlashes($groups[$i]) . "))";
            $fields = array("samaccountname", "distinguishedname", "objectClass");
            if ($sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields))
            {
                $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

                // not a person, look for a group
                if ($entries['count'] == 0 && $recursive) {
                    $filter = "(&(objectCategory=group)(distinguishedName=" . $this->adldap->utilities()->ldapSlashes($groups[$i]) . "))";
                    $fields = array("distinguishedname");
                    if ($sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields)) {
                        $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);
                        if (!isset($entries[0]['distinguishedname'][0])) {
                            continue;
                        }
                        $subGroups = $this->inGroup($entries[0]['distinguishedname'][0], $recursive);
                        if (is_array($subGroups)) {
                            $groupArray = array_merge($groupArray, $subGroups);
                            $groupArray = array_unique($groupArray);
                        }
                    }
                    continue;
                }

                $groupArray[] = $entries[0]['distinguishedname'][0];
            }
        }
        return $groupArray;
    }

    /**
     * Return a list of members in a group
     *
     * @param string $group The group to query
     * @param bool $recursive Recursively get group members
     * @return array|false
     */
    public function members(string $group,bool $recursive = false): array|false
    {
        if (!$this->adldap->getLdapBind()) {
            return false;
        }
        if ($recursive === NULL) {
            $recursive = $this->adldap->getRecursiveGroups();
        } // Use the default option if they haven't set it
        // Search the directory for the members of a group
        $info = $this->info($group, array("member", "cn"));
        $users = $info[0]["member"];
        if (!is_array($users)) {
            return false;
        }

        $userArray = array();

        for ($i = 0; $i < $users["count"]; $i++) {
            $filter = "(&(objectCategory=person)(distinguishedName=" . $this->adldap->utilities()->ldapSlashes($users[$i]) . "))";
            $fields = array("samaccountname", "distinguishedname", "objectClass");
            if ($sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields)) {
                $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

                // not a person, look for a group
                if ($entries['count'] == 0 && $recursive) {
                    $filter = "(&(objectCategory=group)(distinguishedName=" . $this->adldap->utilities()->ldapSlashes($users[$i]) . "))";
                    $fields = array("samaccountname");
                    if ($sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields)) {
                        $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);
                        if (!isset($entries[0]['samaccountname'][0])) {
                            continue;
                        }
                        $subUsers = $this->members($entries[0]['samaccountname'][0], $recursive);
                        if (is_array($subUsers)) {
                            $userArray = array_merge($userArray, $subUsers);
                            $userArray = array_unique($userArray);
                        }
                    }
                    continue;
                } else if ($entries['count'] == 0) {
                    continue;
                }

                if ((!isset($entries[0]['samaccountname'][0]) || $entries[0]['samaccountname'][0] === NULL) && $entries[0]['distinguishedname'][0] !== NULL) {
                    $userArray[] = $entries[0]['distinguishedname'][0];
                } else if ($entries[0]['samaccountname'][0] !== NULL) {
                    $userArray[] = $entries[0]['samaccountname'][0];
                }
            } else {
                continue;
            }
        }
        return $userArray;
    }

    /**
     * Group Information.  Returns an array of raw information about a group.
     * The group name is case sensitive
     *
     * @param null|string $groupName The group name to retrieve info about
     * @param null|array $fields Fields to retrieve
     * @return array|false
     */
    public function info(?string $groupName,?array $fields = NULL): array|false
    {
        if ($groupName === NULL) {
            return false;
        }
        if (!$this->adldap->getLdapBind()) {
            return false;
        }

        if (stristr($groupName, '+')) {
            $groupName = stripslashes($groupName);
        }

        $filter = "(&(objectCategory=group)(name=" . $this->adldap->utilities()->ldapSlashes($groupName) . "))";
        if ($fields === NULL) {
            $fields = array("member", "memberof", "cn", "description", "distinguishedname", "objectcategory", "samaccountname");
        }
        if ($sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields)) {
            $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

            return $entries;
        } else {
            return false;
        }
    }

    /**
     * Group Information.  Returns an collection
     * The group name is case sensitive
     *
     * @param null|string $groupName The group name to retrieve info about
     * @param null|array $fields Fields to retrieve
     * @return adLDAPGroupCollection|false
     */
    public function infoCollection(?string $groupName,?array $fields = NULL): adLDAPGroupCollection|false
    {
        if ($groupName === NULL) {
            return false;
        }
        if (!$this->adldap->getLdapBind()) {
            return false;
        }

        $info = $this->info($groupName, $fields);
        if ($info !== false) {
            $collection = new adLDAPGroupCollection($info, $this->adldap);
            return $collection;
        }
        return false;
    }

    /**
     * Return a complete list of "groups in groups"
     *
     * @param null|string $group The group to get the list from
     * @return array|false
     */
    public function recursiveGroups(?string $group): array|false
    {
        if ($group === NULL) {
            return false;
        }

        $stack = array();
        $processed = array();
        $retGroups = array();

        array_push($stack, $group); // Initial Group to Start with 
        while (count($stack) > 0) {
            $parent = array_pop($stack);
            array_push($processed, $parent);

            $info = $this->info($parent, array("memberof"));

            if (isset($info[0]["memberof"]) && is_array($info[0]["memberof"])) {
                $groups = $info[0]["memberof"];
                if ($groups) {
                    $groupNames = $this->adldap->utilities()->niceNames($groups);
                    $retGroups = array_merge($retGroups, $groupNames); //final groups to return
                    foreach ($groupNames as $id => $groupName) {
                        if (!in_array($groupName, $processed)) {
                            array_push($stack, $groupName);
                        }
                    }
                }
            }
        }

        return $retGroups;
    }

    /**
     * Returns a complete list of the groups in AD based on a SAM Account Type
     *
     * @param string|int|null $sAMAaccountType The account type to return
     * @param bool $includeDescription Whether to return a description
     * @param string $search Search parameters
     * @param bool $sorted Whether to sort the results
     * @return array|false
     */
    public function search(string|int|null $sAMAaccountType = adLDAP::ADLDAP_SECURITY_GLOBAL_GROUP,bool $includeDescription = false,string $search = "*",bool $sorted = true): array|false
    {
        if (!$this->adldap->getLdapBind()) {
            return false;
        }

        $filter = '(&(objectCategory=group)';
        if ($sAMAaccountType !== null) {
            $filter .= '(samaccounttype=' . $sAMAaccountType . ')';
        }
        $filter .= '(cn=' . $search . '))';
        // Perform the search and grab all their details
        $fields = array("samaccountname", "description");
        if ($sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields)) {
            $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

            $groupsArray = array();
            for ($i = 0; $i < $entries["count"]; $i++) {
                if ($includeDescription && strlen($entries[$i]["description"][0]) > 0) {
                    $groupsArray[$entries[$i]["samaccountname"][0]] = $entries[$i]["description"][0];
                } else if ($includeDescription) {
                    $groupsArray[$entries[$i]["samaccountname"][0]] = $entries[$i]["samaccountname"][0];
                } else {
                    array_push($groupsArray, $entries[$i]["samaccountname"][0]);
                }
            }
            if ($sorted) {
                asort($groupsArray);
            }
            return $groupsArray;
        } else {
            return false;
        }
    }

    /**
     * Returns a complete list of all groups in AD
     *
     * @param bool $includeDescription Whether to return a description
     * @param string $search Search parameters
     * @param bool $sorted Whether to sort the results
     * @return array|false
     */
    public function all(bool $includeDescription = false,string $search = "*",bool $sorted = true): array|false
    {
        $groupsArray = $this->search(null, $includeDescription, $search, $sorted);
        return $groupsArray;
    }

    /**
     * Returns a complete list of security groups in AD
     *
     * @param bool $includeDescription Whether to return a description
     * @param string $search Search parameters
     * @param bool $sorted Whether to sort the results
     * @return array|false
     */
    public function allSecurity(bool $includeDescription = false,string $search = "*",bool $sorted = true): array|false
    {
        $groupsArray = $this->search(adLDAP::ADLDAP_SECURITY_GLOBAL_GROUP, $includeDescription, $search, $sorted);
        return $groupsArray;
    }

    /**
     * Returns a complete list of distribution lists in AD
     *
     * @param bool $includeDescription Whether to return a description
     * @param string $search Search parameters
     * @param bool $sorted Whether to sort the results
     * @return array|false
     */
    public function allDistribution(bool $includeDescription = false,string $search = "*",bool $sorted = true): array|false
    {
        $groupsArray = $this->search(adLDAP::ADLDAP_DISTRIBUTION_GROUP, $includeDescription, $search, $sorted);
        return $groupsArray;
    }

    /**
     * Coping with AD not returning the primary group
     * http://support.microsoft.com/?kbid=321360
     *
     * This is a re-write based on code submitted by Bruce which prevents the
     * need to search each security group to find the true primary group
     *
     * @param null|string $gid Group ID
     * @param null|string $usersid User's Object SID
     * @return mixed
     */
    public function getPrimaryGroup(?string $gid,?string $usersid): mixed
    {
        if ($gid === NULL || $usersid === NULL) {
            return false;
        }
        //$sr = false;

        $gsid = substr_replace($usersid, pack('V', $gid), strlen($usersid) - 4, 4);
        $filter = '(objectsid=' . $this->adldap->utilities()->getTextSID($gsid) . ')';
        $fields = array("samaccountname", "distinguishedname");
        if ($sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields)) {
            $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

            if (isset($entries[0]['distinguishedname'][0])) {
                return $entries[0]['distinguishedname'][0];
            }
        }
        return false;
    }

    /**
     * Coping with AD not returning the primary group
     * http://support.microsoft.com/?kbid=321360
     *
     * For some reason it's not possible to search on primarygrouptoken=XXX
     * If someone can show otherwise, I'd like to know about it :)
     * this way is resource intensive and generally a pain in the @#%^
     *
     * @param null|string $gid Group ID
     * @return string|false
     * @deprecated deprecated since version 3.1, see get get_primary_group
     */
    public function cn(?string $gid): string|false
    {
        if ($gid === NULL) {
            return false;
        }
        //$sr = false;
        $r = '';

        $filter = "(&(objectCategory=group)(samaccounttype=" . adLDAP::ADLDAP_SECURITY_GLOBAL_GROUP . "))";
        $fields = array("primarygrouptoken", "samaccountname", "distinguishedname");
        if ($sr = ldap_search($this->adldap->getLdapConnection(), $this->adldap->getBaseDn(), $filter, $fields)) {
            $entries = ldap_get_entries($this->adldap->getLdapConnection(), $sr);

            for ($i = 0; $i < $entries["count"]; $i++) {
                if ($entries[$i]["primarygrouptoken"][0] == $gid) {
                    $r = $entries[$i]["distinguishedname"][0];
                    $i = $entries["count"];
                }
            }

            return $r;
        } else {
            return false;
        }
    }
}
