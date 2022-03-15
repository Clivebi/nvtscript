if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842732" );
	script_version( "2021-09-20T11:27:24+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:27:24 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-05 05:23:26 +0200 (Thu, 05 May 2016)" );
	script_cve_id( "CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115", "CVE-2016-2118" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for samba USN-2950-3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2950-1 fixed vulnerabilities in Samba.
  The fixes introduced in Samba 4.3.8 caused certain regressions and
  interoperability issues.

  This update resolves some of these issues by updating to Samba 4.3.9 in
  Ubuntu 14.04 LTS, Ubuntu 15.10 and Ubuntu 16.04 LTS. Backported regression
  fixes were added to Samba 3.6.25 in Ubuntu 12.04 LTS.

  This advisory was inadvertently published as USN-2950-2 originally.

  Original advisory details:

  Jouni Knuutinen discovered that Samba contained multiple flaws in the
  DCE/RPC implementation. A remote attacker could use this issue to perform
  a denial of service, downgrade secure connections by performing a man in
  the middle attack, or possibly execute arbitrary code. (CVE-2015-5370)
  Stefan Metzmacher discovered that Samba contained multiple flaws in the
  NTLMSSP authentication implementation. A remote attacker could use this
  issue to downgrade connections to plain text by performing a man in the
  middle attack. (CVE-2016-2110)
  Alberto Solino discovered that a Samba domain controller would establish a
  secure connection to a server with a spoofed computer name. A remote
  attacker could use this issue to obtain sensitive information.
  (CVE-2016-2111)
  Stefan Metzmacher discovered that the Samba LDAP implementation did not
  enforce integrity protection. A remote attacker could use this issue to
  hijack LDAP connections by performing a man in the middle attack.
  (CVE-2016-2112)
  Stefan Metzmacher discovered that Samba did not validate TLS certificates.
  A remote attacker could use this issue to spoof a Samba server.
  (CVE-2016-2113)
  Stefan Metzmacher discovered that Samba did not enforce SMB signing even if
  configured to. A remote attacker could use this issue to perform a man in
  the middle attack. (CVE-2016-2114)
  Stefan Metzmacher discovered that Samba did not enable integrity protection
  for IPC traffic. A remote attacker could use this issue to perform a man in
  the middle attack. (CVE-2016-2115)
  Stefan Metzmacher discovered that Samba incorrectly handled the MS-SAMR and
  MS-LSAD protocols. A remote attacker could use this flaw with a man in the
  middle attack to impersonate users and obtain sensitive information from
  the Security Account Manager database. This flaw is known as Badlock.
  (CVE-2016-2118)
  Samba has been updated to 4.3.8 in Ubuntu 14.04 LTS and Ubuntu 15.10.
  Ubuntu 12.04 LTS has been updated to 3.6.25 with backported security fixes.
  In addition to security fixes, the updated packages contain bug fixes,
  new features, and possibly incompatible changes. Configuration changes may
  be required in certain environments." );
	script_tag( name: "affected", value: "samba on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2950-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2950-3/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.3.9+dfsg-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:3.6.25-0ubuntu0.12.04.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:4.3.9+dfsg-0ubuntu0.15.10.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

