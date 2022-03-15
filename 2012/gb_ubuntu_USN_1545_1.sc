if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1545-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841121" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-24 09:56:40 +0530 (Fri, 24 Aug 2012)" );
	script_cve_id( "CVE-2012-3361", "CVE-2012-3447" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_xref( name: "USN", value: "1545-1" );
	script_name( "Ubuntu Update for nova USN-1545-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1545-1" );
	script_tag( name: "affected", value: "nova on Ubuntu 12.04 LTS,
  Ubuntu 11.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Padraig Brady discovered that the fix for CVE-2012-3361 was incomplete and
  an authenticated user could still corrupt arbitrary files on the host
  running Nova. A remote attacker could use this to cause a denial of service
  or possibly gain privileges." );
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
	if(( res = isdpkgvuln( pkg: "python-nova", ver: "2012.1+stable~20120612-3ee026e-0ubuntu1.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "python-nova", ver: "2011.3-0ubuntu6.10", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

