if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853664" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2020-6816", "CVE-2020-6817", "CVE-2021-23980" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-30 23:15:00 +0000 (Tue, 30 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:59:16 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for python-bleach (openSUSE-SU-2021:0552-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0552-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YFAKMJGUZHUTZ53ZAID6PRVP5MSLXPGV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-bleach'
  package(s) announced via the openSUSE-SU-2021:0552-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-bleach fixes the following issues:

  - CVE-2021-23980: Fixed mutation XSS on bleach.clean with specific
       combinations of allowed tags (boo#1184547)

     Update to 3.1.5:

  * replace missing ``setuptools`` dependency with ``packaging``. Thank you
       Benjamin Peterson.

     Update to 3.1.4 (boo#1168280, CVE-2020-6817):

  * ``bleach.clean`` behavior parsing style attributes could result in a
       regular expression denial of service (ReDoS). Calls to ``bleach.clean``
       with an allowed tag with an allowed ``style`` attribute were vulnerable
       to ReDoS. For example, ``bleach.clean(..., attributes={&#x27 a&#x27 :
       [&#x27 style&#x27 ]})``.

  * Style attributes with dashes, or single or double quoted values are
       cleaned instead of passed through.

     update to 3.1.3 (boo#1167379, CVE-2020-6816):

  * Add relative link to code of conduct. (#442)

  * Drop deprecated &#x27 setup.py test&#x27  support. (#507)

  * Test on PyPy 7

  * Drop test support for end of life Python 3.4

  * ``bleach.clean`` behavior parsing embedded MathML and SVG content with
       RCDATA tags did not match browser behavior and could result in a
       mutation XSS. Calls to ``bleach.clean`` with ``strip=False`` and
       ``math`` or ``svg`` tags and one or more of the RCDATA tags ``script``,
       ``noscript``, ``style``, ``noframes``, ``iframe``, ``noembed``, or
       ``xmp`` in the allowed tags whitelist were vulnerable to a mutation XSS." );
	script_tag( name: "affected", value: "'python-bleach' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "python2-bleach", rpm: "python2-bleach~3.1.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-bleach", rpm: "python3-bleach~3.1.5~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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

