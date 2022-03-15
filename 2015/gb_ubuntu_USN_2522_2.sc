if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842118" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-07 07:05:23 +0100 (Sat, 07 Mar 2015)" );
	script_cve_id( "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2419", "CVE-2014-6585", "CVE-2014-6591", "CVE-2014-7923", "CVE-2014-7926", "CVE-2014-9654", "CVE-2014-7940" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for icu USN-2522-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'icu'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2522-1 fixed vulnerabilities in ICU. On
Ubuntu 12.04 LTS, the font patches caused a regression when using LibreOffice Calc.
The patches have been temporarily backed out until the regression is investigated.

We apologize for the inconvenience.

Original advisory details:

It was discovered that ICU incorrectly handled memory operations when
processing fonts. If an application using ICU processed crafted data, an
attacker could cause it to crash or potentially execute arbitrary code with
the privileges of the user invoking the program. This issue only affected
Ubuntu 12.04 LTS. (CVE-2013-1569, CVE-2013-2383, CVE-2013-2384,
CVE-2013-2419)
It was discovered that ICU incorrectly handled memory operations when
processing fonts. If an application using ICU processed crafted data, an
attacker could cause it to crash or potentially execute arbitrary code with
the privileges of the user invoking the program. (CVE-2014-6585,
CVE-2014-6591)
It was discovered that ICU incorrectly handled memory operations when
processing regular expressions. If an application using ICU processed
crafted data, an attacker could cause it to crash or potentially execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2014-7923, CVE-2014-7926, CVE-2014-9654)
It was discovered that ICU collator implementation incorrectly handled
memory operations. If an application using ICU processed crafted data, an
attacker could cause it to crash or potentially execute arbitrary code with
the privileges of the user invoking the program. (CVE-2014-7940)" );
	script_tag( name: "affected", value: "icu on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2522-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2522-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libicu48", ver: "4.8.1.1-3ubuntu0.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

