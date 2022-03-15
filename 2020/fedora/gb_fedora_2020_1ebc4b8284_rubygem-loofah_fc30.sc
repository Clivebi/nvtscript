if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877536" );
	script_version( "2021-07-20T02:00:49+0000" );
	script_cve_id( "CVE-2019-15587" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-20 02:00:49 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-17 03:15:00 +0000 (Thu, 17 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-03-01 04:02:51 +0000 (Sun, 01 Mar 2020)" );
	script_name( "Fedora: Security Advisory for rubygem-loofah (FEDORA-2020-1ebc4b8284)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2020-1ebc4b8284" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XMCWPLYPNIWYAY443IZZJ4IHBBLIHBP5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-loofah'
  package(s) announced via the FEDORA-2020-1ebc4b8284 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Loofah is a general library for manipulating and transforming HTML/XML
documents and fragments. It&#39, s built on top of Nokogiri and libxml2, so
it&#39, s fast and has a nice API.
Loofah excels at HTML sanitization (XSS prevention). It includes some
nice HTML sanitizers, which are based on HTML5lib&#39, s whitelist, so it
most likely won&#39, t make your codes less secure." );
	script_tag( name: "affected", value: "'rubygem-loofah' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "rubygem-loofah", rpm: "rubygem-loofah~2.2.3~4.fc30", rls: "FC30" ) )){
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

