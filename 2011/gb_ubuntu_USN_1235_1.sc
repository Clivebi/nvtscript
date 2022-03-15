if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1235-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840779" );
	script_version( "2019-08-06T11:17:21+0000" );
	script_tag( name: "last_modification", value: "2019-08-06 11:17:21 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1235-1" );
	script_cve_id( "CVE-2009-1297" );
	script_name( "Ubuntu Update for open-iscsi USN-1235-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU8\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1235-1" );
	script_tag( name: "affected", value: "open-iscsi on Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Colin Watson discovered that iscsi_discovery in Open-iSCSI did not safely
  create temporary files. A local attacker could exploit this to overwrite
  arbitrary files with root privileges." );
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
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "open-iscsi", ver: "2.0.865-1ubuntu3.5", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

