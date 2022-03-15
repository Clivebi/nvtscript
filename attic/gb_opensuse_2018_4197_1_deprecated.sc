if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852198" );
	script_version( "2021-09-20T14:50:00+0000" );
	script_tag( name: "deprecated", value: TRUE );
	script_cve_id( "CVE-2018-15750", "CVE-2018-15751" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 14:50:00 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-20 01:17:00 +0000 (Thu, 20 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-12-20 07:33:59 +0100 (Thu, 20 Dec 2018)" );
	script_name( "openSUSE: Security Advisory for salt (openSUSE-SU-2018:4197-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_xref( name: "openSUSE-SU", value: "2018:4197-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00052.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'salt'
  package(s) announced via the openSUSE-SU-2018:4197-1 advisory.

  This NVT has been replaced by OID:1.3.6.1.4.1.25623.1.0.814578" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for salt fixes the following issues:

  - Crontab module fix: file attributes option missing (boo#1114824)

  - Fix git_pillar merging across multiple __env__ repositories (boo#1112874)

  - Bugfix: unable to detect os arch when RPM is not installed (boo#1114197)

  - Fix LDAP authentication issue when a valid token is generated by the
  salt-api even when invalid user credentials are passed. (U#48901)

  - Improved handling of LDAP group id. gid is no longer treated as a
  string, which could have lead to faulty group creations. (boo#1113784)

  - Fix remote command execution and incorrect access control when using
  salt-api. (boo#1113699) (CVE-2018-15751)

  - Fix Directory traversal vulnerability when using salt-api. Allows an
  attacker to determine what files exist on a server when querying /run or
  /events. (boo#1113698) (CVE-2018-15750)

  - Add multi-file support and globbing to the filetree (U#50018)

  - Bugfix: supportconfig non-root permission issues (U#50095)

  - Open profiles permissions to everyone for read-only

  - Preserving signature in 'module.run' state (U#50049)

  - Install default salt-support profiles

  - Remove unit test, came from a wrong branch. Fix merging failure.

  - Add CPE_NAME for osversion* grain parsing

  - Get os_family for RPM distros from the RPM macros

  - Install support profiles

  - Fix async call to process manager (boo#1110938)

  - Salt-based supportconfig implementation (technology preview)

  - Bugfix: any unicode string of length 16 will raise TypeError

  - Fix IPv6 scope (boo#1108557)

  - Handle zypper ZYPPER_EXIT_NO_REPOS exit code (boo#1108834, boo#1109893)

  - Bugfix for pkg_resources crash (boo#1104491)

  - Fix loosen azure sdk dependencies in azurearm cloud driver (boo#1107333)

  - Fix broken 'resolve_capabilities' on Python 3 (boo#1108995)
  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1574=1" );
	script_tag( name: "affected", value: "salt on openSUSE Leap 42.3." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
exit( 66 );

