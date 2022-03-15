if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877546" );
	script_version( "2020-03-10T09:12:31+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-10 09:12:31 +0000 (Tue, 10 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-05 04:04:45 +0000 (Thu, 05 Mar 2020)" );
	script_name( "Fedora: Security Advisory for opensmtpd (FEDORA-2020-283dc7f094)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-283dc7f094" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/N44LZREZEP77UOARDCXANVDFSHT2E5YX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'opensmtpd'
  package(s) announced via the FEDORA-2020-283dc7f094 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "OpenSMTPD is a FREE implementation of the server-side SMTP protocol as defined
by RFC 5321, with some additional standard extensions. It allows ordinary
machines to exchange e-mails with other systems speaking the SMTP protocol.
Started out of dissatisfaction with other implementations, OpenSMTPD nowadays
is a fairly complete SMTP implementation. OpenSMTPD is primarily developed
by Gilles Chehade, Eric Faurot and Charles Longeau, with contributions from
various OpenBSD hackers. OpenSMTPD is part of the OpenBSD Project.
The software is freely usable and re-usable by everyone under an ISC license.

This package uses standard 'alternatives' mechanism, you may call
'/usr/sbin/alternatives --set mta /usr/sbin/sendmail.opensmtpd'
if you want to switch to OpenSMTPD MTA immediately after install, and
'/usr/sbin/alternatives --set mta /usr/sbin/sendmail.sendmail' to revert
back to Sendmail as a default mail daemon." );
	script_tag( name: "affected", value: "'opensmtpd' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "opensmtpd", rpm: "opensmtpd~6.6.4p1~1.fc31", rls: "FC31" ) )){
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

