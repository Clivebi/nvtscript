if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841403" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-04-19 10:09:06 +0530 (Fri, 19 Apr 2013)" );
	script_cve_id( "CVE-2013-0454" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_name( "Ubuntu Update for samba USN-1802-1" );
	script_xref( name: "USN", value: "1802-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1802-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	script_tag( name: "affected", value: "samba on Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that Samba incorrectly handled CIFS share attributes when
  SMB2 was used. A remote authenticated user could possibly gain write access
  to certain shares, bypassing the intended permissions." );
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
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:3.6.3-2ubuntu2.6", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

