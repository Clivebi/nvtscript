if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1178-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840712" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1178-1" );
	script_cve_id( "CVE-2011-2513", "CVE-2011-2514" );
	script_name( "Ubuntu Update for icedtea-web USN-1178-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1178-1" );
	script_tag( name: "affected", value: "icedtea-web on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Omair Majid discovered that an unsigned Web Start application
  or applet could determine the path to the cache directory used
  to store downloaded class and jar files by querying class loader
  properties. This could allow a remote attacker to discover a user's
  name and home directory path. (CVE-2011-2513)

  Omair Majid discovered that an unsigned Web Start application could
  manipulate the content of the security warning dialog message to show
  different file names in prompts. This could allow a remote attacker
  to confuse a user into granting access to a different file than they
  believe they are granting access to. This issue only affected Ubuntu
  11.04. (CVE-2011-2514)" );
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
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "icedtea6-plugin", ver: "6b20-1.9.9-0ubuntu1~10.10.2", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "icedtea6-plugin", ver: "6b20-1.9.9-0ubuntu1~10.04.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "icedtea-netx", ver: "1.1.1-0ubuntu1~11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "icedtea-plugin", ver: "1.1.1-0ubuntu1~11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

