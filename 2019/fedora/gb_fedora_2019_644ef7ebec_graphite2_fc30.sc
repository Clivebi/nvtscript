if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876771" );
	script_version( "2021-09-01T08:01:24+0000" );
	script_cve_id( "CVE-2018-7999" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 08:01:24 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-06 14:15:00 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-09-07 02:24:25 +0000 (Sat, 07 Sep 2019)" );
	script_name( "Fedora Update for graphite2 FEDORA-2019-644ef7ebec" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-644ef7ebec" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LVWOKYZZDEMG6VSG53KAGUOHUIIQ7CND" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'graphite2'
  package(s) announced via the FEDORA-2019-644ef7ebec advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Graphite2 is a project within SILs Non-Roman Script Initiative and Language
Software Development groups to provide rendering capabilities for complex
non-Roman writing systems. Graphite can be used to create smart fonts capable
of displaying writing systems with various complex behaviors. With respect to
the Text Encoding Model, Graphite handles the 'Rendering' aspect of writing
system implementation." );
	script_tag( name: "affected", value: "'graphite2' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "graphite2", rpm: "graphite2~1.3.13~1.fc30", rls: "FC30" ) )){
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

