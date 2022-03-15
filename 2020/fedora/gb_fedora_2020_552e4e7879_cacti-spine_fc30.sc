if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877555" );
	script_version( "2021-07-19T02:00:45+0000" );
	script_cve_id( "CVE-2020-8813" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-19 02:00:45 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-25 18:15:00 +0000 (Tue, 25 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-03-10 04:04:35 +0000 (Tue, 10 Mar 2020)" );
	script_name( "Fedora: Security Advisory for cacti-spine (FEDORA-2020-552e4e7879)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2020-552e4e7879" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/M77SS33IDVNGBU566TK2XVULPW3RXUQ4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cacti-spine'
  package(s) announced via the FEDORA-2020-552e4e7879 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Spine is a supplemental poller for Cacti that makes use of pthreads to achieve
excellent performance." );
	script_tag( name: "affected", value: "'cacti-spine' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "cacti-spine", rpm: "cacti-spine~1.2.10~1.fc30", rls: "FC30" ) )){
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

