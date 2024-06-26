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
 * @subpackage Utils
 * @author Scott Barnett, Richard Hyland
 * @copyright (c) 2006-2012 Scott Barnett, Richard Hyland
 * @license http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html LGPLv2.1
 * @revision $Revision: 97 $
 * @version 4.0.4
 * @link http://adldap.sourceforge.net/
 */
require_once(dirname(__FILE__) . '/../adLDAP.php');

/**
 * UTILITY FUNCTIONS
 */
class adLDAPUtils
{
    const ADLDAP_VERSION = '4.1.0';

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
     * Take an LDAP query and return the nice names, without all the LDAP prefixes (eg. CN, DN)
     *
     * @param array $groups
     * @return array
     */
    public function niceNames(array $groups): array
    {

        $groupArray = [];
        //PHP Warning: Trying to access array offset on value of type null
        if (isset($groups["count"])) {
            for ($i = 0; $i < $groups["count"]; $i++) { // For each group
                $line = $groups[$i];

                if (strlen($line) > 0) {
                    // More presumptions, they're all prefixed with CN=
                    // so we ditch the first three characters and the group
                    // name goes up to the first comma
                    $bits = explode(",", $line);
                    $groupArray[] = substr($bits[0], 3, (strlen($bits[0]) - 3));
                }
            }
        }
        return $groupArray;
    }

    /**
     * Escape characters for use in an ldap_create function
     *
     * @param string $str
     * @return string
     */
    public function escapeCharacters(string $str): string
    {
        $str = str_replace(",", "\,", $str);
        return $str;
    }

    /**
     * Escape strings for the use in LDAP filters
     *
     * DEVELOPERS SHOULD BE DOING PROPER FILTERING IF THEY'RE ACCEPTING USER INPUT
     * Ported from Perl's Net::LDAP::Util escape_filter_value
     *
     * @param string $str The string the parse
     * @return string
     * @author Port by Andreas Gohr <andi@splitbrain.org>
     */
    public function ldapSlashes(string $str): string
    {
        // PHP7 -  preg_replace(): The /e modifier is no longer supported, use preg_replace_callback instead
        //return preg_replace('/([\x00-\x1F\*\(\)\\\\])/e','"\\\\\".join("",unpack("H2","$1"))',$str);
        return ldap_escape($str);
    }

    /**
     * Converts a string GUID to a hexdecimal value so it can be queried
     *
     * @param string $strGUID A string representation of a GUID
     * @return string
     */
    public function strGuidToHex(string $strGUID): string
    {
        $strGUID = str_replace('-', '', $strGUID);

        $octet_str = '\\' . substr($strGUID, 6, 2);
        $octet_str .= '\\' . substr($strGUID, 4, 2);
        $octet_str .= '\\' . substr($strGUID, 2, 2);
        $octet_str .= '\\' . substr($strGUID, 0, 2);
        $octet_str .= '\\' . substr($strGUID, 10, 2);
        $octet_str .= '\\' . substr($strGUID, 8, 2);
        $octet_str .= '\\' . substr($strGUID, 14, 2);
        $octet_str .= '\\' . substr($strGUID, 12, 2);
        //$octet_str .= '\\' . substr($strGUID, 16, strlen($strGUID));
        for ($i = 16; $i <= (strlen($strGUID) - 2); $i++) {
            if (($i % 2) == 0) {
                $octet_str .= '\\' . substr($strGUID, $i, 2);
            }
        }

        return $octet_str;
    }

    /**
     * Convert a binary SID to a text SID
     *
     * @param string $binsid A Binary SID
     * @return string
     */
    public function getTextSID(string $binsid): string
    {
        $hex_sid = bin2hex($binsid);
        $rev = hexdec(substr($hex_sid, 0, 2));
        $subcount = hexdec(substr($hex_sid, 2, 2));
        $auth = hexdec(substr($hex_sid, 4, 12));
        $result = "$rev-$auth";

        for ($x = 0; $x < $subcount; $x++) {
            $subauth[$x] =
                hexdec($this->littleEndian(substr($hex_sid, 16 + ($x * 8), 8)));
            $result .= "-" . $subauth[$x];
        }

        // Cheat by tacking on the S-
        return 'S-' . $result;
    }

    /**
     * Converts a little-endian hex number to one that hexdec() can convert
     *
     * @param string $hex A hex code
     * @return string
     */
    public function littleEndian(string $hex): string
    {
        $result = '';
        for ($x = strlen($hex) - 2; $x >= 0; $x = $x - 2) {
            $result .= substr($hex, $x, 2);
        }
        return $result;
    }

    /**
     * Converts a binary attribute to a string
     *
     * @param string $bin A binary LDAP attribute
     * @return string
     */
    public function binaryToText(string $bin): string
    {
        $hex_guid = bin2hex($bin);
        $hex_guid_to_guid_str = '';
        for ($k = 1; $k <= 4; ++$k) {
            $hex_guid_to_guid_str .= substr($hex_guid, 8 - 2 * $k, 2);
        }
        $hex_guid_to_guid_str .= '-';
        for ($k = 1; $k <= 2; ++$k) {
            $hex_guid_to_guid_str .= substr($hex_guid, 12 - 2 * $k, 2);
        }
        $hex_guid_to_guid_str .= '-';
        for ($k = 1; $k <= 2; ++$k) {
            $hex_guid_to_guid_str .= substr($hex_guid, 16 - 2 * $k, 2);
        }
        $hex_guid_to_guid_str .= '-' . substr($hex_guid, 16, 4);
        $hex_guid_to_guid_str .= '-' . substr($hex_guid, 20);
        return strtoupper($hex_guid_to_guid_str);
    }

    /**
     * Converts a binary GUID to a string GUID
     *
     * @param null|string $binaryGuid The binary GUID attribute to convert
     * @return string
     */
    public function decodeGuid(?string $binaryGuid): string
    {
        if ($binaryGuid === null) {
            return "Missing compulsory field [binaryGuid]";
        }

        $strGUID = $this->binaryToText($binaryGuid);
        return $strGUID;
    }

    /**
     * Convert a boolean value to a string
     * You should never need to call this yourself
     *
     * @param bool $bool Boolean value
     * @return string
     */
    public function boolToStr(bool $bool): string
    {
        return ($bool) ? 'TRUE' : 'FALSE';
    }

    /**
     * Convert 8bit characters e.g. accented characters to UTF8 encoded characters
     */
    public function encode8Bit(mixed &$item,string|int $key): void
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
     * Get the current class version number
     *
     * @return string
     */
    public function getVersion(): string
    {
        return self::ADLDAP_VERSION;
    }

    /**
     * Round a Windows timestamp down to seconds and remove the seconds between 1601-01-01 and 1970-01-01
     * An integer data type is a non-decimal number between -2147483648 and 2147483647 in 32 bit systems, and between -9223372036854775808 and 9223372036854775807 in 64 bit systems. A value greater (or lower) than this, will be stored as float, because it exceeds the limit of an integer.
     *
     * @param int $windowsTime
     * @return int $unixTime
     */
    public static function convertWindowsTimeToUnixTime(int $windowsTime): int
    {
        $unixTime = round($windowsTime / 10000000) - 11644477200;
        return $unixTime;
    }
}
