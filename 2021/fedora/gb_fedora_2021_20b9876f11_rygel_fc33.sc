if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878996" );
	script_version( "2021-03-05T07:23:50+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-05 07:23:50 +0000 (Fri, 05 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-02-27 04:02:10 +0000 (Sat, 27 Feb 2021)" );
	script_name( "Fedora: Security Advisory for rygel (FEDORA-2021-20b9876f11)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-20b9876f11" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2NB4JXO5Y35UV7DFATHNU5W32UXE34RC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rygel'
  package(s) announced via the FEDORA-2021-20b9876f11 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Rygel is a home media solution that allows you to easily share audio, video and
pictures, and control of media player on your home network. In technical terms
it is both a UPnP AV MediaServer and MediaRenderer implemented through a plug-in
mechanism. Interoperability with other devices in the market is achieved by
conformance to very strict requirements of DLNA and on the fly conversion of
media to format that client devices are capable of handling." );
	script_tag( name: "affected", value: "'rygel' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "rygel", rpm: "rygel~0.40.1~1.fc33", rls: "FC33" ) )){
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
