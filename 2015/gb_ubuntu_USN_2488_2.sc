if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842092" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-14 05:03:52 +0100 (Sat, 14 Feb 2015)" );
	script_cve_id( "CVE-2013-6497", "CVE-2014-9328" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for clamav USN-2488-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2488-1 fixed a vulnerability in ClamAV
for Ubuntu 14.10, Ubuntu 14.04 LTS, and Ubuntu 12.04 LTS. This update provides the
corresponding update for Ubuntu 10.04 LTS.

Original advisory details:

Sebastian Andrzej Siewior discovered that ClamAV incorrectly handled
certain upack packer files. An attacker could possibly use this issue to
cause ClamAV to crash, resulting in a denial of service, or possibly
execute arbitrary code." );
	script_tag( name: "affected", value: "clamav on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2488-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2488-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "clamav", ver: "0.98.6+dfsg-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

