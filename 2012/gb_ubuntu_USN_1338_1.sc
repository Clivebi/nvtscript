if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1338-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840877" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-01-25 11:16:27 +0530 (Wed, 25 Jan 2012)" );
	script_cve_id( "CVE-2011-4623" );
	script_xref( name: "USN", value: "1338-1" );
	script_name( "Ubuntu Update for rsyslog USN-1338-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.04" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1338-1" );
	script_tag( name: "affected", value: "rsyslog on Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Peter Eisentraut discovered that Rsyslog would not properly perform input
  validation when configured to use imfile. If an attacker were able to
  craft messages in a file that Rsyslog monitored, an attacker could cause a
  denial of service. The imfile module is disabled by default in Ubuntu." );
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
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "rsyslog", ver: "4.6.4-2ubuntu4.2", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

