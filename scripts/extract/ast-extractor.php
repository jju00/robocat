<?php

require '/home/zerovirus/web/nuclei_project/php-parser/vendor/autoload.php';

use PhpParser\ParserFactory;
use PhpParser\Node;

if ($argc < 3) {
    echo "Usage: php grav_ast_dump.php /path/to/grav output_dir\n";
    exit(1);
}

$rootDir = rtrim($argv[1], "/");
$outputDir = rtrim($argv[2], "/");

if (!is_dir($rootDir)) {
    echo "Invalid Grav directory\n";
    exit(1);
}

if (!is_dir($outputDir)) {
    mkdir($outputDir, 0777, true);
}

$parser = (new ParserFactory)->createForNewestSupportedVersion();

/* ======================================================
   AST → 배열 변환
====================================================== */

function nodeToArray($node) {

    if ($node instanceof Node) {

        $result = [
            'type' => $node->getType(),
        ];

        foreach ($node->getSubNodeNames() as $name) {
            $result[$name] = nodeToArray($node->$name);
        }

        return $result;
    }

    if (is_array($node)) {
        return array_map('nodeToArray', $node);
    }

    return $node;
}

/* ======================================================
   파일명 안전 변환
====================================================== */

function safeFilename($path) {
    $path = str_replace(['/', '\\', ':'], '_', $path);
    return $path;
}

/* ======================================================
   전체 PHP 파일 순회
====================================================== */

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($rootDir, FilesystemIterator::SKIP_DOTS)
);

$total = 0;
$parsed = 0;
$failed = 0;

foreach ($iterator as $file) {

    if (!$file->isFile()) continue;
    if (strtolower($file->getExtension()) !== "php") continue;

    $total++;

    $path = $file->getPathname();
    $relativePath = str_replace($rootDir . '/', '', $path);

    $code = @file_get_contents($path);
    if (!$code) {
        $failed++;
        continue;
    }

    try {
        $ast = $parser->parse($code);

        if (!$ast) {
            $failed++;
            continue;
        }

        $astArray = nodeToArray($ast);

        $outFile = $outputDir . '/' . safeFilename($relativePath) . '.json';

        file_put_contents(
            $outFile,
            json_encode($astArray, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );

        $parsed++;

    } catch (Throwable $e) {
        $failed++;
        continue;
    }
}

echo "Done\n";
echo "Total PHP files: $total\n";
echo "Parsed: $parsed\n";
echo "Failed: $failed\n";