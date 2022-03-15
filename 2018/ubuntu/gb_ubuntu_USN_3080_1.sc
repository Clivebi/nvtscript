if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843735" );
	script_version( "$Revision: 14288 $" );
	script_cve_id( "CVE-2016-0775", "CVE-2016-2533", "CVE-2014-3589" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2018-10-26 06:13:22 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for python-imaging USN-3080-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	script_xref( name: "USN", value: "3080-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3080-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-imaging'
  package(s) announced via the USN-3080-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Eric Soroos discovered that the Python Imaging Library incorrectly handled
certain malformed FLI or PhotoCD files. A remote attacker could use this
issue to cause Python Imaging Library to crash, resulting in a denial of
service. (CVE-2016-0775, CVE-2016-2533)

Andrew Drake discovered that the Python Imaging Library incorrectly validated
input. A remote attacker could use this to cause Python Imaging Library to
crash, resulting in a denial of service. (CVE-2014-3589)" );
	script_tag( name: "affected", value: "python-imaging on Ubuntu 12.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
	if(( res = isdpkgvuln( pkg: "python-imaging", ver: "1.1.7-4ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

