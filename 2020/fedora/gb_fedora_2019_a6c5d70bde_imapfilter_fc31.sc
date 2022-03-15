if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877156" );
	script_version( "2021-07-16T11:00:51+0000" );
	script_cve_id( "CVE-2016-10937" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-16 11:00:51 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-03 15:15:00 +0000 (Wed, 03 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:28:58 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for imapfilter FEDORA-2019-a6c5d70bde" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-a6c5d70bde" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GBNDFMAIUA6PQMV2P6OKIP7JZQEWX7D2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'imapfilter'
  package(s) announced via the FEDORA-2019-a6c5d70bde advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "IMAPFilter is a mail filtering utility. It connects to remote mail servers
using the Internet Message Access Protocol (IMAP), sends searching queries
to the server and processes mailboxes based on the results. It can be used
to delete, copy, move, flag, etc. messages residing in mailboxes at the
same or different mail servers. The 4rev1 and 4 versions of the IMAP
protocol are supported." );
	script_tag( name: "affected", value: "'imapfilter' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "imapfilter", rpm: "imapfilter~2.6.15~1.fc31", rls: "FC31" ) )){
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

