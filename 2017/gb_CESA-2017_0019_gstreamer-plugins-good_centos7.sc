if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882625" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-10 05:49:55 +0100 (Tue, 10 Jan 2017)" );
	script_cve_id( "CVE-2016-9634", "CVE-2016-9635", "CVE-2016-9636", "CVE-2016-9807", "CVE-2016-9808" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for gstreamer-plugins-good CESA-2017:0019 centos7" );
	script_tag( name: "summary", value: "Check the version of gstreamer-plugins-good" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "GStreamer is a streaming media framework
based on graphs of filters which operate on media data. The gstreamer-plugins-good
packages contain a collection of well-supported plug-ins of good quality and under
the LGPL license.

Security Fix(es):

  * Multiple flaws were discovered in GStreamer's FLC/FLI/FLX media file
format decoding plug-in. A remote attacker could use these flaws to cause
an application using GStreamer to crash or, potentially, execute arbitrary
code with the privileges of the user running the application.
(CVE-2016-9634, CVE-2016-9635, CVE-2016-9636, CVE-2016-9808)

  * An invalid memory read access flaw was found in GStreamer's FLC/FLI/FLX
media file format decoding plug-in. A remote attacker could use this flaw
to cause an application using GStreamer to crash. (CVE-2016-9807)

Note: This update removes the vulnerable FLC/FLI/FLX plug-in." );
	script_tag( name: "affected", value: "gstreamer-plugins-good on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:0019" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-January/022197.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "gstreamer-plugins-good", rpm: "gstreamer-plugins-good~0.10.31~12.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gstreamer-plugins-good-devel-docs", rpm: "gstreamer-plugins-good-devel-docs~0.11.31~12.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

