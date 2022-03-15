if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879693" );
	script_version( "2021-08-20T14:00:58+0000" );
	script_cve_id( "CVE-2021-30465" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 14:00:58 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-10 05:15:00 +0000 (Sat, 10 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-03 06:24:38 +0000 (Thu, 03 Jun 2021)" );
	script_name( "Fedora: Security Advisory for runc (FEDORA-2021-0440f235a0)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-0440f235a0" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/35ZW6NBZSBH5PWIT7JU4HXOXGFVDCOHH" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'runc'
  package(s) announced via the FEDORA-2021-0440f235a0 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The runc command can be used to start containers which are packaged
in accordance with the Open Container Initiative&#39, s specifications,
and to manage containers running under runc." );
	script_tag( name: "affected", value: "'runc' package(s) on Fedora 34." );
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
	if(!isnull( res = isrpmvuln( pkg: "runc", rpm: "runc~1.0.0~378.rc95.fc34", rls: "FC34" ) )){
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

