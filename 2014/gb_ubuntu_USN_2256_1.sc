if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841872" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-01 22:09:12 +0530 (Tue, 01 Jul 2014)" );
	script_cve_id( "CVE-2014-3497" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Ubuntu Update for swift USN-2256-1" );
	script_tag( name: "affected", value: "swift on Ubuntu 14.04 LTS" );
	script_tag( name: "insight", value: "John Dickinson discovered that Swift did not properly quote
the WWW-Authenticate header value. If a user were tricked into navigating to a
malicious Swift URL, an attacker could conduct cross-site scripting
attacks. With cross-site scripting vulnerabilities, if a user were tricked
into viewing server output during a crafted server request, a remote
attacker could exploit this to modify the contents, or steal confidential
data, within the same domain." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2256-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2256-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'swift'
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
	if(( res = isdpkgvuln( pkg: "python-swift", ver: "1.13.1-0ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

