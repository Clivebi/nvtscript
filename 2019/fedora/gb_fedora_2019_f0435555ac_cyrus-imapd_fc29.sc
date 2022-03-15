if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876471" );
	script_version( "2021-09-02T12:01:30+0000" );
	script_cve_id( "CVE-2019-11356" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 12:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-14 05:15:00 +0000 (Wed, 14 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-06-08 02:16:38 +0000 (Sat, 08 Jun 2019)" );
	script_name( "Fedora Update for cyrus-imapd FEDORA-2019-f0435555ac" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-f0435555ac" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PICSZDC3UGEUZ27VXGGM6OFI67D3KKLZ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cyrus-imapd'
  package(s) announced via the FEDORA-2019-f0435555ac advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Cyrus IMAP (Internet Message Access Protocol) server provides access to
personal mail, system-wide bulletin boards, news-feeds, calendar and contacts
through the IMAP, JMAP, NNTP, CalDAV and CardDAV protocols. The Cyrus IMAP
server is a scalable enterprise groupware system designed for use from small to
large enterprise environments using technologies based on well-established Open
Standards.

A full Cyrus IMAP implementation allows a seamless mail and bulletin board
environment to be set up across one or more nodes. It differs from other IMAP
server implementations in that it is run on sealed nodes, where users are not
normally permitted to log in. The mailbox database is stored in parts of the
filesystem that are private to the Cyrus IMAP system. All user access to mail
is through software using the IMAP, IMAPS, JMAP, POP3, POP3S, KPOP, CalDAV
and/or CardDAV protocols.

The private mailbox database design gives the Cyrus IMAP server large
advantages in efficiency, scalability, and administratability. Multiple
concurrent read/write connections to the same mailbox are permitted. The server
supports access control lists on mailboxes and storage quotas on mailbox
hierarchies." );
	script_tag( name: "affected", value: "'cyrus-imapd' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "cyrus-imapd", rpm: "cyrus-imapd~3.0.10~1.fc29", rls: "FC29" ) )){
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

