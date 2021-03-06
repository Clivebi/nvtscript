if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877454" );
	script_version( "2020-02-14T06:25:11+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-02-14 06:25:11 +0000 (Fri, 14 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-02-09 04:03:16 +0000 (Sun, 09 Feb 2020)" );
	script_name( "Fedora: Security Advisory for libasr (FEDORA-2020-a861033a4d)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-a861033a4d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OYHEEOYP5MUM22DPD3NXPG6HRVVXE2WW" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libasr'
  package(s) announced via the FEDORA-2020-a861033a4d advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Libasr allows to run DNS queries and perform hostname resolutions in a fully
asynchronous fashion. The implementation is thread-less, fork-less, and does not
make use of signals or other 'tricks' that might get in the developer&#39, s
way.
The API was initially developed for the OpenBSD operating system, where it is
natively supported.

This library is intended to bring this interface to other systems. It is
originally provided as a support library for the portable version of the
OpenSMTPD daemon, but it can be used in any other contexts." );
	script_tag( name: "affected", value: "'libasr' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "libasr", rpm: "libasr~1.0.4~1.fc31", rls: "FC31" ) )){
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

