if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842409" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-15 05:05:45 +0200 (Sat, 15 Aug 2015)" );
	script_cve_id( "CVE-2015-5352", "CVE-2015-5600" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openssh USN-2710-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Moritz Jodeit discovered that OpenSSH
incorrectly handled usernames when using PAM authentication. If an additional
vulnerability were discovered in the OpenSSH unprivileged child process, this
issue could allow a remote attacker to perform user impersonation. (CVE number
pending) Moritz Jodeit discovered that OpenSSH incorrectly handled context memory
when using PAM authentication. If an additional vulnerability were
discovered in the OpenSSH unprivileged child process, this issue could
allow a remote attacker to bypass authentication or possibly execute
arbitrary code. (CVE number pending)

Jann Horn discovered that OpenSSH incorrectly handled time windows for
X connections. A remote attacker could use this issue to bypass certain
access restrictions. (CVE-2015-5352)

It was discovered that OpenSSH incorrectly handled keyboard-interactive
authentication. In a non-default configuration, a remote attacker could
possibly use this issue to perform a brute-force password attack.
(CVE-2015-5600)" );
	script_tag( name: "affected", value: "openssh on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2710-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2710-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "openssh-server", ver: "1:6.6p1-2ubuntu2.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "openssh-server", ver: "1:5.9p1-5ubuntu1.6", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

