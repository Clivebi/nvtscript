if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841939" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-08-22 05:57:22 +0200 (Fri, 22 Aug 2014)" );
	script_cve_id( "CVE-2014-4615" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Ubuntu Update for ceilometer USN-2311-2" );
	script_tag( name: "affected", value: "ceilometer on Ubuntu 14.04 LTS" );
	script_tag( name: "insight", value: "USN-2311-1 fixed vulnerabilities in pyCADF. This update
provides the corresponding updates for OpenStack Ceilometer.

Original advisory details:

Zhi Kun Liu discovered that pyCADF incorrectly filtered certain tokens.
An attacker could possibly use this issue to obtain authentication tokens
used in REST requests." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2311-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2311-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ceilometer'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "ceilometer-common", ver: "2014.1.2-0ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

