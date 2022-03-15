if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879812" );
	script_version( "2021-08-23T06:00:57+0000" );
	script_cve_id( "CVE-2021-34825" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-23 06:00:57 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-30 05:15:00 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-07-06 03:18:52 +0000 (Tue, 06 Jul 2021)" );
	script_name( "Fedora: Security Advisory for quassel (FEDORA-2021-75cec6e6da)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-75cec6e6da" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7ZFWRN5P2WG23MWMVAEVV3YBHGFJHDSW" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'quassel'
  package(s) announced via the FEDORA-2021-75cec6e6da advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Quassel IRC is a modern, distributed IRC client,
meaning that one (or multiple) client(s) can attach
to and detach from a central core --
much like the popular combination of screen and a
text-based IRC client such as WeeChat, but graphical" );
	script_tag( name: "affected", value: "'quassel' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "quassel", rpm: "quassel~0.13.1~8.fc34", rls: "FC34" ) )){
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

