<?php

require '/home/zerovirus/web/nuclei_project/php-parser/vendor/autoload.php';

use PhpParser\ParserFactory;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;

if ($argc < 2) {
    echo "Usage: php grav_event_route_extractor.php /path/to/grav\n";
    exit(1);
}

$rootDir = rtrim($argv[1], "/");

class EventRouteVisitor extends NodeVisitorAbstract {

    private $namespace = "";
    private $currentClass = null;

    public $eventRoutes = [];

    public function enterNode(Node $node) {

        // -------------------------
        // Namespace 처리
        // -------------------------
        if ($node instanceof Node\Stmt\Namespace_) {
            $this->namespace = $node->name ? $node->name->toString() : "";
        }

        // -------------------------
        // Class 처리
        // -------------------------
        if ($node instanceof Node\Stmt\Class_) {
            if ($node->name instanceof Node\Identifier) {
                $this->currentClass = $node->name->toString();
            }
        }

        // -------------------------
        // getSubscribedEvents 탐지
        // -------------------------
        if ($node instanceof Node\Stmt\ClassMethod &&
            $node->name instanceof Node\Identifier &&
            $node->name->toString() === "getSubscribedEvents") {

            if (!is_array($node->stmts)) {
                return;
            }

            foreach ($node->stmts as $stmt) {

                if (!$stmt instanceof Node\Stmt\Return_) continue;

                if (!$stmt->expr instanceof Node\Expr\Array_) continue;

                foreach ($stmt->expr->items as $item) {

                    if (!$item) continue;
                    if (!$item->key instanceof Node\Scalar\String_) continue;

                    $eventName = $item->key->value;
                    $handlerMethod = "unknown";

                    $value = $item->value;

                    // -------------------------
                    // 1️⃣ 'event' => 'method'
                    // -------------------------
                    if ($value instanceof Node\Scalar\String_) {
                        $handlerMethod = $value->value;
                    }

                    // -------------------------
                    // 2️⃣ 배열 형태 처리
                    // -------------------------
                    elseif ($value instanceof Node\Expr\Array_) {

                        if (isset($value->items[0])) {

                            $first = $value->items[0]->value;

                            // ['method', priority]
                            if ($first instanceof Node\Scalar\String_) {
                                $handlerMethod = $first->value;
                            }

                            // [['method', priority]]
                            elseif ($first instanceof Node\Expr\Array_) {

                                if (isset($first->items[0])) {

                                    $inner = $first->items[0]->value;

                                    if ($inner instanceof Node\Scalar\String_) {
                                        $handlerMethod = $inner->value;
                                    }
                                }
                            }
                        }
                    }

                    // -------------------------
                    // Fully Qualified Class 구성
                    // -------------------------
                    $fqClass = "";

                    if ($this->namespace) {
                        $fqClass .= $this->namespace . "\\";
                    }

                    if ($this->currentClass) {
                        $fqClass .= $this->currentClass;
                    }

                    $this->eventRoutes[] = [
                        "event" => $eventName,
                        "handler" => $fqClass . "::" . $handlerMethod
                    ];
                }
            }
        }
    }

    public function leaveNode(Node $node) {

        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClass = null;
        }
    }
}

// -------------------------
// Parser 준비
// -------------------------
$parser = (new ParserFactory)->createForNewestSupportedVersion();
$visitor = new EventRouteVisitor();

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($rootDir, FilesystemIterator::SKIP_DOTS)
);

foreach ($iterator as $file) {

    if (!$file->isFile()) continue;
    if ($file->getExtension() !== "php") continue;

    $path = str_replace("\\", "/", $file->getPathname());

    // Grav plugin 중심 분석
    if (strpos($path, "user/plugins") === false) continue;

    $code = @file_get_contents($path);
    if ($code === false) continue;

    try {

        $ast = $parser->parse($code);
        if (!$ast) continue;

        $traverser = new NodeTraverser();
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

    } catch (Throwable $e) {
        continue;
    }
}

echo json_encode(
    $visitor->eventRoutes,
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
);
