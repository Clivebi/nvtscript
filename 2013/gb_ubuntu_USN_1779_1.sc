if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1779-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841377" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-03-28 09:51:00 +0530 (Thu, 28 Mar 2013)" );
	script_cve_id( "CVE-2013-0240", "CVE-2013-1799" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_xref( name: "USN", value: "1779-1" );
	script_name( "Ubuntu Update for gnome-online-accounts USN-1779-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnome-online-accounts'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|12\\.10)" );
	script_tag( name: "affected", value: "gnome-online-accounts on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10" );
	script_tag( name: "insight", value: "It was discovered that GNOME Online Accounts did not properly check SSL
  certificates when configuring online accounts. If a remote attacker were
  able to perform a man-in-the-middle attack, this flaw could be exploited to
  alter or compromise credentials and confidential information." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
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
	if(( res = isdpkgvuln( pkg: "gnome-online-accounts", ver: "3.4.0-0ubuntu1.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgoa-1.0-0", ver: "3.4.0-0ubuntu1.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "gnome-online-accounts", ver: "3.2.1-0ubuntu1.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgoa-1.0-0", ver: "3.2.1-0ubuntu1.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "gnome-online-accounts", ver: "3.6.0-0ubuntu1.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgoa-1.0-0", ver: "3.6.0-0ubuntu1.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

