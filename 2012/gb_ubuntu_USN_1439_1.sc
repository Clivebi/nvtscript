if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1439-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841003" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-08 12:37:37 +0530 (Tue, 08 May 2012)" );
	script_cve_id( "CVE-2012-2094", "CVE-2012-2144" );
	script_xref( name: "USN", value: "1439-1" );
	script_name( "Ubuntu Update for horizon USN-1439-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1439-1" );
	script_tag( name: "affected", value: "horizon on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Matthias Weckbecker discovered a cross-site scripting (XSS) vulnerability
  in Horizon via the log viewer refrash mechanism. If a user were tricked
  into viewing a specially crafted log message, a remote attacker could
  exploit this to modify the contents or steal confidential data within the
  same domain. (CVE-2012-2094)

  Thomas Biege discovered a session fixation vulnerability in Horizon. An
  attacker could exploit this to potentially allow access to unauthorized
  information and capabilities. (CVE-2012-2144)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
	if(( res = isdpkgvuln( pkg: "python-django-horizon", ver: "2012.1-0ubuntu8.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

