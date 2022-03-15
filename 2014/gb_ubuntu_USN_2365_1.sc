if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841989" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-10-01 17:00:28 +0530 (Wed, 01 Oct 2014)" );
	script_cve_id( "CVE-2014-6051", "CVE-2014-6052", "CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for libvncserver USN-2365-1" );
	script_tag( name: "insight", value: "Nicolas Ruff discovered that LibVNCServer incorrectly handled memory when
being advertised large screen sizes by the server. If a user were tricked
into connecting to a malicious server, an attacker could use this issue to
cause a denial of service, or possibly execute arbitrary code.
(CVE-2014-6051, CVE-2014-6052)

Nicolas Ruff discovered that LibVNCServer incorrectly handled large
ClientCutText messages. A remote attacker could use this issue to cause a
server to crash, resulting in a denial of service. (CVE-2014-6053)

Nicolas Ruff discovered that LibVNCServer incorrectly handled zero scaling
factor values. A remote attacker could use this issue to cause a server to
crash, resulting in a denial of service. (CVE-2014-6054)

Nicolas Ruff discovered that LibVNCServer incorrectly handled memory in the
file transfer feature. A remote attacker could use this issue to cause a
server to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2014-6055)" );
	script_tag( name: "affected", value: "libvncserver on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2365-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2365-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvncserver'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libvncserver0", ver: "0.9.9+dfsg-1ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libvncserver0", ver: "0.9.8.2-2ubuntu1.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

