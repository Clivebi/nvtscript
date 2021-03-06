if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841817" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-12 09:13:32 +0530 (Mon, 12 May 2014)" );
	script_cve_id( "CVE-2013-6491" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "Ubuntu Update for quantum USN-2208-2" );
	script_tag( name: "affected", value: "quantum on Ubuntu 12.10" );
	script_tag( name: "insight", value: "USN-2208-1 fixed vulnerabilities in OpenStack Cinder. This
update provides the corresponding updates for OpenStack Quantum.

Original advisory details:

JuanFra Rodriguez Cardoso discovered that OpenStack Cinder did not enforce
SSL connections when Nova was configured to use QPid and qpid_protocol is
set to 'ssl'. If a remote attacker were able to perform a man-in-the-middle
attack, this flaw could be exploited to view sensitive information. Ubuntu
does not use QPid with Nova by default." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2208-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2208-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'quantum'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.10" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "python-quantum", ver: "2012.2.4-0ubuntu1.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

