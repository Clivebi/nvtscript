if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842767" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-19 05:20:59 +0200 (Thu, 19 May 2016)" );
	script_cve_id( "CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115", "CVE-2016-2118" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for samba USN-2950-4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2950-1 fixed vulnerabilities in Samba.
  The backported fixes introduced in Ubuntu 12.04 LTS caused interoperability
  issues. This update fixes compatibility with certain NAS devices, and allows
  connecting to Samba 3.6 servers by relaxing the 'client ipc signing' parameter
  to 'auto'.

  We apologize for the inconvenience.

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
	script_tag( name: "affected", value: "samba on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2950-4" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2950-4/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
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
	if(( res = isdpkgvuln( pkg: "samba", ver: "2:3.6.25-0ubuntu0.12.04.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

