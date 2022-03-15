if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877841" );
	script_version( "2021-07-14T02:00:49+0000" );
	script_cve_id( "CVE-2020-9365", "CVE-2020-9274" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-14 02:00:49 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 19:32:00 +0000 (Mon, 16 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-05-16 03:19:36 +0000 (Sat, 16 May 2020)" );
	script_name( "Fedora: Security Advisory for pure-ftpd (FEDORA-2020-84fb0920fd)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-84fb0920fd" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U5DBVHJCXWRSJPNJQCJQCKZF6ZDPZCKA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pure-ftpd'
  package(s) announced via the FEDORA-2020-84fb0920fd advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Pure-FTPd is a fast, production-quality, standard-comformant FTP server,
based upon Troll-FTPd. Unlike other popular FTP servers, it has no known
security flaw, it is really trivial to set up and it is especially designed
for modern Linux and FreeBSD kernels (setfsuid, sendfile, capabilities) .
Features include PAM support, IPv6, chroot()ed home directories, virtual
domains, built-in LS, anti-warez system, bandwidth throttling, FXP, bounded
ports for passive downloads, UL/DL ratios, native LDAP and SQL support,
Apache log files and more.
Rebuild switches:

  - -without ldap     disable ldap support

  - -without mysql    disable mysql support

  - -without pgsql    disable postgresql support

  - -without extauth  disable external authentication

  - -without tls      disable SSL/TLS" );
	script_tag( name: "affected", value: "'pure-ftpd' package(s) on Fedora 31." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "pure-ftpd", rpm: "pure-ftpd~1.0.49~5.fc31", rls: "FC31" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

