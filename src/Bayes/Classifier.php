<?php
namespace Watermelon\Engine\Bayes;
use Watermelon\Protect\PostFilter;

class Classifier
{
    /**
     * @var TokenizerInterface
     */
    protected $tokenizer;

    /**
     * @var array
     */
    protected $labels = array();

    /**
     * @var array
     */
    protected $docs = array();

    /**
     * @var array
     */
    protected $tokens = array();

    /**
     * @var array
     */
    protected $data = array();

    /**
     * Constructor.
     *
     * @param TokenizerInterface $tokenizer
     */
    public $model = array();
    public function __construct(TokenizerInterface $tokenizer)
    {
        $this->filter = new PostFilter;
        $this->tokenizer = $tokenizer;
    }
    /**
     * Trains the classifier one text+label combination a time
     *
     * @param string $label
     * @param string $text
     */
    public function train($label, $text)
    {
        $label =  $this->filter->strip(strtolower($label));
        $text  =  $this->filter->strip(strtolower($text));

        $tokens = $this->tokenizer->tokenize($text);

        if (!isset($this->labels[$label])) {
            $this->labels[$label] = 0;
            $this->data[$label] = [];
            $this->docs[$label] = 0;
        }

        foreach ($tokens as $token) {
            if (!isset($this->tokens[$token])) {
                $this->tokens[$token] = 0;
            }
            if (!isset($this->data[$label][$token])) {
                $this->data[$label][$token] = 0;
            }

            $this->labels[$label]++;
            $this->tokens[$token]++;
            $this->data[$label][$token]++;
        }

        $this->docs[$label]++;

        $this->model = array(
            'labels' =>  $this->labels,
            'docs'   =>  $this->docs,
            'tokens' =>  $this->tokens,
            'data'   =>  $this->data
        );
    }

    /**
     * Generates trained model file
     *
     * @param  string $modelDir
     * @param  string $modelName
     * @return 'model location'
     */
    public function generateModel($modelDir, $modelName)
    {
        $modelDir = $this->filter->strip($modelDir);
        $modelName = $this->filter->strip($modelName);
        if (is_dir($modelDir)) {
            $location = $modelDir.'/'.$modelName.'.model';
            $trained = gzcompress(serialize($this->model));
            file_put_contents($location, $trained);
            return $location;
        } else {
            //create the model directory
            mkdir($modelDir);
            $this->generateModel($modelDir, $modelName);
        }
    }

    /**
     * Resets the classifier
     */
    public function reset()
    {
        $this->labels = array();
        $this->docs = array();
        $this->tokens = array();
        $this->data = array();
    }

    /**
     * @param  string $token
     * @param  string $label
     * @return int
     */
    protected function inversedTokenCount($token, $label)
    {
        $data = $this->data;

        $totalTokenCount = $this->tokens[$token];

        $totalLabelTokenCount = isset($data[$label][$token]) ? $data[$label][$token] : 0;

        $retval = $totalTokenCount - $totalLabelTokenCount;

        return $retval;
    }

    /**
     * @param  string $label
     * @return number
     */
    protected function inversedDocCount($label)
    {
        $data = $this->docs;

        unset($data[$label]);

        return array_sum($data);
    }

    /**
     * Classifies a text and returns the probability (score) per label without a saved model
     *
     * @param  string $text
     * @return array
     */
    private function classify($text)
    {
        $text = $this->filter->strip(strtolower($text));
        $totalDocCount = array_sum($this->docs);

        $tokens = $this->tokenizer->tokenize($text);

        $scores = array();

        foreach ($this->labels as $label => $labelCount) {
            $logSum = 0;

            $docCount = $this->docs[$label];
            $inversedDocCount = $totalDocCount - $docCount;

            if (0 === $inversedDocCount) {
                continue;
            }

            foreach ($tokens as $token) {
                $totalTokenCount = isset($this->tokens[$token]) ? $this->tokens[$token] : 0;

                if (0 === $totalTokenCount) {
                    continue;
                }

                $tokenCount         = isset($this->data[$label][$token]) ? $this->data[$label][$token] : 0;
                $inversedTokenCount = $this->inversedTokenCount($token, $label);

                $tokenProbabilityPositive = $tokenCount / $docCount;
                $tokenProbabilityNegative = $inversedTokenCount / $inversedDocCount;

                $probability = $tokenProbabilityPositive / ($tokenProbabilityPositive + $tokenProbabilityNegative);

                $probability = ((1 * 0.5) + ($totalTokenCount * $probability)) / (1 + $totalTokenCount);

                if (0 === $probability) {
                    $probability = 0.01;
                } elseif (1 === $probability) {
                    $probability = 0.99;
                }

                $logSum += log(1 - $probability) - log($probability);
            }

            $scores[$label] = 1 / (1 + exp($logSum));
        }

        arsort($scores, SORT_NUMERIC);

        return $scores;
    }
    /**
    * Classifies a text from existing model
    *
    * @param  string $text
    * @param string $modelLocation
    * @return array
    */
    public function classifyFromModel($text, $modelLocation)
    {
        if (!file_exists($modelLocation)) {
            throw new Exception('Error: No model find in this location '.$modelLocation);
        }
        //check moldel extension
        if (pathinfo($modelLocation, PATHINFO_EXTENSION) !== 'model') {
            throw new Exception('Error: Invalid model extension. Please make sure you are using the right model path');
        }

        $this->model = unserialize(gzuncompress(file_get_contents($modelLocation)));

        $this->labels = $this->model['labels'];
        $this->docs   = $this->model['docs'];
        $this->tokens = $this->model['tokens'];
        $this->data   = $this->model['data'];

        return $this->classify($text);
    }
}