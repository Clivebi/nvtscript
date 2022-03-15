if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876707" );
	script_version( "2021-09-01T13:01:35+0000" );
	script_cve_id( "CVE-2019-10098", "CVE-2019-10092", "CVE-2019-10097" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 13:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-07 19:01:00 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-08-23 02:23:49 +0000 (Fri, 23 Aug 2019)" );
	script_name( "Fedora Update for mod_md FEDORA-2019-099575a123" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-099575a123" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4Q3VMBINKQZAQWXDDMQCNJMYJHPT5R46" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'mod_md' package(s) announced via the FEDORA-2019-099575a123 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "This module manages common properties of
  domains for one or more virtual hosts. Specifically it can use the ACME protocol
  (RFC Draft) to automate certificate provisioning. These will be configured for
  managed domains and their virtual hosts automatically. This includes renewal of
  certificates before they expire." );
	script_tag( name: "affected", value: "'mod_md' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "mod_md", rpm: "mod_md~2.0.8~2.fc30", rls: "FC30" ) )){
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

